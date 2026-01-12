#ifndef __WIFIBROADCAST_RADIOTAP_HEADER_HPP__
#define __WIFIBROADCAST_RADIOTAP_HEADER_HPP__

#include "Helper.hpp"
extern "C" {
#include "../../lib/radiotap/radiotap.h"
#include "../../lib/radiotap/radiotap_iter.h"
};

#include <endian.h>

#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>
#include <string>
#include <vector>

#include "../Ieee80211Header.hpp"
#include "../wifibroadcast_spdlog.h"

// everything must be in little endian byte order http://www.radiotap.org/
static_assert(__BYTE_ORDER == __LITTLE_ENDIAN,
              "This code is written for little endian only !");

namespace radiotap::tx {

static constexpr auto MCS_MAX = 31;
static constexpr auto MCS_MIN = 0;

// https://stackoverflow.com/questions/47981/how-do-you-set-clear-and-toggle-a-single-bit
// http://www.radiotap.org/
static uint32_t writePresenceBitfield(
    const std::vector<ieee80211_radiotap_presence> &valuesToBePresent) {
  uint32_t present = 0;
  for (const auto &valueToBePresent : valuesToBePresent) {
    present |= 1 << valueToBePresent;
  }
  return present;
}

// http://www.radiotap.org/fields/MCS.html
struct MCS {
  uint8_t known = 0;
  uint8_t flags = 0;
  uint8_t modulationIndex = 0;
} __attribute__((packed));
}  // namespace radiotap::tx

// To inject packets we need 2 radiotap fields: "TX flags"  and the "MCS field"
struct RadiotapHeaderWithTxFlagsAndMCS {
  uint8_t version = 0;
  uint8_t padding = 0;
  uint16_t length = 13;
  // http://www.radiotap.org/
  uint32_t presence = 0;
  // http://www.radiotap.org/fields/TX%20flags.html
  uint16_t txFlags = 0;
  // http://www.radiotap.org/fields/MCS.html
  //  mcs is more than just the mcs index. Be carefully !
  radiotap::tx::MCS mcs{};
} __attribute__((packed));
static_assert(sizeof(RadiotapHeaderWithTxFlagsAndMCS) == 13);

// To inject packets we need a proper radiotap header. The fields of importance
// for use are: 1) "TX flags" 2) "MCS field" This class holds the bytes for a
// proper radiotap header after constructing it with the user-selectable Params
class RadiotapHeaderTx {
 public:
  static constexpr auto SIZE_BYTES = 13;
  // these are the params in use by OpenHD right now
  struct UserSelectableParams {
    // 20 or 40 mhz channel width. I do not recommend using 40mhz channel width
    // even though it might provide higher throughput.
    int bandwidth = 20;
    // I do not recommend using a short guard interval
    bool short_gi = false;
    // https://en.wikipedia.org/wiki/Space%E2%80%93time_block_code
    int stbc = 0;
    // https://en.wikipedia.org/wiki/Low-density_parity-check_code#:~:text=In%20information%20theory%2C%20a%20low,subclass%20of%20the%20bipartite%20graph).
    bool ldpc = false;
    // https://www.digitalairwireless.com/articles/blog/demystifying-modulation-and-coding-scheme-mcs-index-values
    // https://mcsindex.com/
    int mcs_index = 3;
    // depends on the driver
    bool set_flag_tx_no_ack = false;
  };
  // Make sure that this is the only constructor
  explicit RadiotapHeaderTx(const UserSelectableParams &params) {
    if (params.mcs_index < radiotap::tx::MCS_MIN ||
        params.mcs_index > radiotap::tx::MCS_MAX) {
      throw std::runtime_error(
          fmt::format("Unsupported MCS index {}", params.mcs_index));
    }
    if (!(params.bandwidth == 5 || params.bandwidth == 10 ||
          params.bandwidth == 20 || params.bandwidth == 40)) {
      throw std::runtime_error(
          fmt::format("Unsupported bandwidth: {}", params.bandwidth));
    }
    if (!(params.stbc == 0 || params.stbc == 1 || params.stbc == 2 ||
          params.stbc == 3)) {
      throw std::runtime_error(
          fmt::format("Unsupported STBC: {}", params.stbc));
    }
    // size is fixed here
    radiotapHeaderData.length = SIZE_BYTES;
    // we use 2 radiotap fields, tx flags and mcs field
    radiotapHeaderData.presence = radiotap::tx::writePresenceBitfield(
        {IEEE80211_RADIOTAP_TX_FLAGS, IEEE80211_RADIOTAP_MCS});

    // in wifibroadcast we never want ack from the receiver - well, this is
    // true, but rtl8812au driver actually uses this one a bit differently
    if (params.set_flag_tx_no_ack) {
      radiotapHeaderData.txFlags =
          IEEE80211_RADIOTAP_F_TX_NOACK;  //| IEEE80211_RADIOTAP_F_TX_CTS |
                                          // IEEE80211_RADIOTAP_F_TX_RTS
    } else {
      radiotapHeaderData.txFlags = 0;
    }
    // now onto the "MCS field"
    radiotapHeaderData.mcs.known =
        (IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW |
         IEEE80211_RADIOTAP_MCS_HAVE_GI | IEEE80211_RADIOTAP_MCS_HAVE_STBC |
         IEEE80211_RADIOTAP_MCS_HAVE_FEC);
    // write the mcs index
    radiotapHeaderData.mcs.modulationIndex = params.mcs_index;

    switch (params.bandwidth) {
      case 20:
        radiotapHeaderData.mcs.flags |= IEEE80211_RADIOTAP_MCS_BW_20;
        break;
      case 40:
        radiotapHeaderData.mcs.flags |= IEEE80211_RADIOTAP_MCS_BW_40;
        break;
      default:
        assert(true);
    }

    if (params.short_gi) {
      radiotapHeaderData.mcs.flags |= IEEE80211_RADIOTAP_MCS_SGI;
    }

    if (params.ldpc) {
      radiotapHeaderData.mcs.flags |= IEEE80211_RADIOTAP_MCS_FEC_LDPC;
    }

    switch (params.stbc) {
      case 0:
        break;
      case 1:
        radiotapHeaderData.mcs.flags |= (IEEE80211_RADIOTAP_MCS_STBC_1
                                         << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
        break;
      case 2:
        radiotapHeaderData.mcs.flags |= (IEEE80211_RADIOTAP_MCS_STBC_2
                                         << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
        break;
      case 3:
        radiotapHeaderData.mcs.flags |= (IEEE80211_RADIOTAP_MCS_STBC_3
                                         << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
        break;
      default:
        assert(true);
    }
  };
  const uint8_t *getData() const {
    return (const uint8_t *)&radiotapHeaderData;
  }
  constexpr std::size_t getSize() const { return SIZE_BYTES; }
  static std::string user_params_to_string(const UserSelectableParams &params) {
    return fmt::format("BW:{} MCS:{} SGI:{} STBC:{} LDPC:{} NO_ACK:{}",
                       params.bandwidth, params.mcs_index, params.short_gi,
                       params.stbc, params.ldpc, params.set_flag_tx_no_ack);
  }

 private:
  RadiotapHeaderWithTxFlagsAndMCS radiotapHeaderData;
} __attribute__((packed));
static_assert(sizeof(RadiotapHeaderTx) == RadiotapHeaderTx::SIZE_BYTES,
              "ALWAYS TRUE");
static_assert(sizeof(RadiotapHeaderWithTxFlagsAndMCS) ==
                  RadiotapHeaderTx::SIZE_BYTES,
              "ALWAYS TRUE");

namespace RadiotapHelper {

// [RadiotapHeaderTx | Ieee80211HeaderRaw | customHeader (if not size 0) |
// payload (if not size 0)]
static std::vector<uint8_t> create_radiotap_wifi_packet(
    const RadiotapHeaderTx &radiotapHeader,
    const Ieee80211HeaderRaw &ieee80211Header, const uint8_t *data,
    int data_len) {
  std::vector<uint8_t> packet(radiotapHeader.getSize() +
                              sizeof(ieee80211Header.data) + data_len);
  uint8_t *p = packet.data();
  // radiotap header
  memcpy(p, radiotapHeader.getData(), radiotapHeader.getSize());
  p += radiotapHeader.getSize();
  // ieee80211 wbDataHeader
  memcpy(p, &ieee80211Header.data, sizeof(ieee80211Header.data));
  p += sizeof(ieee80211Header.data);
  memcpy(p, data, data_len);
  p += data_len;
  return packet;
}

}  // namespace RadiotapHelper

#endif  //__WIFIBROADCAST_RADIOTAP_HEADER_HPP__