#ifndef CONSTI10_WIFIBROADCAST_WB_TRANSMITTER_H
#define CONSTI10_WIFIBROADCAST_WB_TRANSMITTER_H
//
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>
// 2020 Constantin Geier
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <queue>
#include <thread>
#include <variant>

#include "Encryption.hpp"
#include "FECDisabled.hpp"
#include "FECEnabled.hpp"
#include "HelperSources/Helper.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "RawTransmitter.hpp"
#include "wifibroadcast-spdlog.h"
#include "wifibroadcast.hpp"
//#include <atomic>
#include "../readerwriterqueue/readerwritercircularbuffer.h"
#include "WBTransmitterStats.hpp"

// dynamic fec block size, NONE = use fixed k value
enum class FEC_VARIABLE_INPUT_TYPE {RTP_H264, RTP_H265, RTP_MJPEG };

// the following settings are only needed if fec is enabled
struct TxFecOptions{
  // overhead / amount of additional data (in percent) generated by the n of fec secondary packets.
  // replaced the fec "N" parameter since we cannot use this notation when changing the fec block size on the fly.
  // Note that this will "roughly" be the overhead, but not exactly.
  int overhead_percentage = 50;
  // Set to 0 for variable block length
  // with variable fec block length we can increase k to the max without creating a buffered frame stuck in FEC,and also eliminate the sometimes
  // existing "stuck frame" due to a block not aligned with the latest frame. However, it is a bit complicated to set up, since the FEC encoder
  // is not agnostic of the incoming data anymore.
  // Set to 1 or greater for a fixed block length. With a fixed block length, you do not need to set the rtp video codec
  int fixed_k =8;
};

// Note: The UDP port is missing as an option here, since it is not an option for WFBTransmitter anymore.
// Only an option when you run this program via the command line.
struct TOptions {
  // the radio port is what is used as an index to multiplex multiple streams (telemetry,video,...)
  // into the one wfb stream
  uint8_t radio_port = 1;
  // file for encryptor
  // make optional for ease of use - with no keypair given the default "seed" is used
  std::optional<std::string> keypair = std::nullopt;
  // wlan interface to send packets with
  std::string wlan;
  // Even though setting the fec_k parameter / n of primary fragments creates similar characteristics as a link
  // without fec, we have a special impl. when fec is disabled, since there we allow packets out of order and with fec_k == 1 you'd have
  // packet re-ordering / packets out of order are not possible.
  bool enable_fec= true;
  // the following settings are only needed if fec is enabled
  TxFecOptions tx_fec_options{};
};

class WBTransmitter {
 public:
  /**
   * Each instance has to be assigned with a Unique ID to differentiate between streams on the RX
   * It does all the FEC encoding & encryption for this stream, then uses PcapTransmitter to inject the generated packets
   * FEC can be either enabled or disabled.
   * When run as an executable from the command line, a UDPReceiver is created for forwarding data to an instance of this class.
   * @param radiotapHeader the radiotap header that is used for injecting, contains configurable data like the mcs index.
   * @param options1 options for this instance, some of them are forwarded to the receiver instance.
   */
  WBTransmitter(RadiotapHeader::UserSelectableParams radioTapHeaderParams, TOptions options1,std::shared_ptr<spdlog::logger> opt_console= nullptr);
  WBTransmitter(const WBTransmitter &) = delete;
  WBTransmitter &operator=(const WBTransmitter &) = delete;
  ~WBTransmitter();
  /**
   * feed a new packet to this instance.
   * Depending on the selected mode, this might add FEC packets or similar.
   * If the packet size exceeds the max packet size, the packet is dropped.
   * @param buf packet data buffer
   * @param size packet data buffer size
   */
  void feedPacket(const uint8_t *buf, size_t size,std::optional<bool> end_block=std::nullopt);
  void feedPacket(std::shared_ptr<std::vector<uint8_t>> packet,std::optional<bool> end_block);
  void tmp_feed_frame_fragments(const std::vector<std::shared_ptr<std::vector<uint8_t>>>& frame_fragments,
                                bool use_fixed_fec_instead);
  // Split frame into more than 1 fec block if it is too big to do the computation in one FEC block
  void tmp_split_and_feed_frame_fragments(const std::vector<std::shared_ptr<std::vector<uint8_t>>>& frame_fragments,
                                          int max_block_size);
  /**
  * Create a verbose string that gives debugging information about the current state of this wb receiver.
   * Since this one only reads, it is safe to call from any thread.
   * Note that this one doesn't print to stdout.
  * @return a string without new line at the end.
  */
  [[nodiscard]] std::string createDebugState() const;

  // These are for updating parameters at run time
  // change the mcs index (will be applied on the next enqueued packet)
  void update_mcs_index(uint8_t mcs_index);

  // change the fec percentage value (will be applied on the next fec step)
  // only valid if fec is enabled
  void update_fec_percentage(uint32_t fec_percentage);

  // Change the fec k parameter. Note that we only support changing the fec_k
  // (fixed or variable) if fec is enabled, NOT switching between fec enabled / disabled
  // (Since we use FEC enabled for video and FEC disabled for telemetry anyways)
  void update_fec_k(int fec_k);

  std::size_t get_estimate_buffered_packets(){
    return m_data_queue.size_approx();
  }
  WBTxStats get_latest_stats();
  // only valid when actually doing FEC
  FECTxStats get_latest_fec_stats();
 private:
  // send the current session key via WIFI (located in mEncryptor)
  void sendSessionKey();
  // for the FEC encoder
  void sendFecPrimaryOrSecondaryFragment(uint64_t nonce, const uint8_t *payload, size_t payloadSize);
  // send packet by prefixing data with the current IEE and Radiotap header
  void sendPacket(const AbstractWBPacket &abstractWbPacket);
  const TOptions options;
  const bool kEnableFec;
  // only used if FEC is enabled
  TxFecOptions m_tx_fec_options;
  // On the tx, either one of those two is active at the same time
  std::unique_ptr<FECEncoder> m_fec_encoder = nullptr;
  std::unique_ptr<FECDisabledEncoder> m_fec_disabled_encoder = nullptr;
  std::shared_ptr<spdlog::logger> m_console;
  // this one is used for injecting packets
  PcapTransmitter m_pcap_transmitter;
  //RawSocketTransmitter mPcapTransmitter;
  // Used to encrypt the packets
  Encryptor m_encryptor;
  // Header for injected packets
  Ieee80211Header mIeee80211Header;
  // this one never changes,also used as a header for injected packets.
  RadiotapHeader::UserSelectableParams m_radioTapHeaderParams;
  std::mutex m_radiotapHeaderMutex;
  RadiotapHeader mRadiotapHeader;
  uint16_t ieee80211_seq = 0;
  // statistics for console
  // n of packets fed to the instance
  int64_t nInputPackets = 0;
  // n of actually injected packets
  int64_t nInjectedPackets = 0;
  // n of injected session key packets
  int64_t nInjectedSessionKeypackets=0;
  // count of bytes we got passed (aka for example, what the video encoder produced - does not include FEC)
  uint64_t count_bytes_data_provided=0;
  BitrateCalculator bitrate_calculator_data_provided{};
  // count of bytes we injected into the wifi card
  uint64_t count_bytes_data_injected=0;
  // a tx error is thrown if injecting the packet takes longer than MAX_SANE_INJECTION_TIME,
  // which hints at a overflowing tx queue (unfortunately I don't know a way to directly get the tx queue yet)
  // However, this hint can be misleading - for example, during testing (MCS set to 3) and with about 5MBit/s video after FEC
  // I get about 5 tx error(s) per second with my atheros, but it works fine. This workaround also seems to not work at all
  // with the RTL8812au.
  uint64_t count_tx_injections_error_hint=0;
  static constexpr std::chrono::nanoseconds MAX_SANE_INJECTION_TIME=std::chrono::milliseconds(5);
  BitrateCalculator bitrate_calculator_injected_bytes{};
  PacketsPerSecondCalculator _packets_per_second_calculator{};
  std::chrono::steady_clock::time_point session_key_announce_ts{};
  WBSessionKeyPacket sessionKeyPacket;
  //
  std::atomic<uint16_t> m_curr_seq_nr=0;
  uint64_t m_n_dropped_packets=0;
 private:
  struct Item{
    std::optional<bool> end_block;
    std::shared_ptr<std::vector<uint8_t>> data;
  };
  // extra data queue, to smooth out input from udp port AND more importantly, have a queue we can reason about
  // in contrast to the linux udp socket buffer, which we cannot get any information about.
  moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<Item>> m_data_queue{128};
  std::unique_ptr<std::thread> m_process_data_thread;
  bool m_process_data_thread_run=true;
  void loop_process_data();
  void feedPacket2(const uint8_t *buf, size_t size,std::optional<bool> end_block);
};

#endif //CONSTI10_WIFIBROADCAST_WB_TRANSMITTER_H
