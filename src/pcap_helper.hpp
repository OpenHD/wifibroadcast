//
// Created by consti10 on 17.12.22.
//

#ifndef WIFIBROADCAST_SRC_PCAP_HELPER_H_
#define WIFIBROADCAST_SRC_PCAP_HELPER_H_

#include <string>

#include <pcap/pcap.h>

namespace wifibroadcast::pcap_helper{

// debugging
static std::string tstamp_types_to_string(int* ts_types,int n){
  std::stringstream ss;
  ss<<"[";
  for(int i=0;i<n;i++){
    const char *name = pcap_tstamp_type_val_to_name(ts_types[i]);
    const char *description = pcap_tstamp_type_val_to_description(ts_types[i]);
    ss<<name<<"="<<description<<",";
  }
  ss<<"]";
  return ss.str();
}

// Set timestamp type to PCAP_TSTAMP_HOST if available
static void iteratePcapTimestamps(pcap_t *ppcap) {
  int *availableTimestamps;
  const int nTypes = pcap_list_tstamp_types(ppcap, &availableTimestamps);
  wifibroadcast::log::get_default()->debug("TS types:{}", wifibroadcast::pcap_helper::tstamp_types_to_string(availableTimestamps,nTypes));
  //"N available timestamp types "<<nTypes<<"\n";
  for (int i = 0; i < nTypes; i++) {
    if (availableTimestamps[i] == PCAP_TSTAMP_HOST) {
      wifibroadcast::log::get_default()->debug("Setting timestamp to host");
      pcap_set_tstamp_type(ppcap, PCAP_TSTAMP_HOST);
    }
  }
  pcap_free_tstamp_types(availableTimestamps);
}

// creates a pcap handle for the given wlan and sets common params for wb
// returns nullptr on failure, a valid pcap handle otherwise
static pcap_t *open_pcap_rx(const std::string &wlan) {
  pcap_t *ppcap= nullptr;
  char errbuf[PCAP_ERRBUF_SIZE];
  ppcap = pcap_create(wlan.c_str(), errbuf);
  if (ppcap == nullptr) {
    wifibroadcast::log::get_default()->error("Unable to open interface {} in pcap: {}", wlan.c_str(), errbuf);
    return nullptr;
  }
  iteratePcapTimestamps(ppcap);
  if (pcap_set_snaplen(ppcap, 4096) != 0) wifibroadcast::log::get_default()->error("set_snaplen failed");
  if (pcap_set_promisc(ppcap, 1) != 0) wifibroadcast::log::get_default()->error("set_promisc failed");
  //if (pcap_set_rfmon(ppcap, 1) !=0) wifibroadcast::log::get_default()->error("set_rfmon failed");
  if (pcap_set_timeout(ppcap, -1) != 0) wifibroadcast::log::get_default()->error("set_timeout failed");
  //if (pcap_set_buffer_size(ppcap, 2048) !=0) wifibroadcast::log::get_default()->error("set_buffer_size failed");
  // Important: Without enabling this mode pcap buffers quite a lot of packets starting with version 1.5.0 !
  // https://www.tcpdump.org/manpages/pcap_set_immediate_mode.3pcap.html
  if (pcap_set_immediate_mode(ppcap, true) != 0){
    wifibroadcast::log::get_default()->warn("pcap_set_immediate_mode failed: {}",pcap_geterr(ppcap));
  }
  if (pcap_activate(ppcap) != 0){
    wifibroadcast::log::get_default()->error("pcap_activate failed: {}",pcap_geterr(ppcap));
  }
  if (pcap_setnonblock(ppcap, 1, errbuf) != 0){
    wifibroadcast::log::get_default()->error("set_nonblock failed: {}",errbuf);
  }
  return ppcap;
}

// copy paste from svpcom
static pcap_t *open_pcap_tx(const std::string &wlan) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *p = pcap_create(wlan.c_str(), errbuf);
  if (p == nullptr) {
    wifibroadcast::log::get_default()->error("Unable to open interface {} in pcap: {}", wlan.c_str(), errbuf);
  }
  if (pcap_set_snaplen(p, 4096) != 0) wifibroadcast::log::get_default()->warn("set_snaplen failed");
  if (pcap_set_promisc(p, 1) != 0) wifibroadcast::log::get_default()->warn("set_promisc failed");
  //if (pcap_set_rfmon(p, 1) !=0) wifibroadcast::log::get_default()->warn("set_rfmon failed";
  // Used to be -1 at some point, which is undefined behaviour. -1 can cause issues on older kernels, according to @Pete
  const int timeout_ms=10;
  if (pcap_set_timeout(p, timeout_ms) != 0) wifibroadcast::log::get_default()->warn("set_timeout {} failed",timeout_ms);
  //if (pcap_set_buffer_size(p, 2048) !=0) wifibroadcast::log::get_default()->warn("set_buffer_size failed";
  // NOTE: Immediate not needed on TX
  if (pcap_activate(p) != 0){
    wifibroadcast::log::get_default()->error("pcap_activate failed: {}",
                                             pcap_geterr(p));
  }
  //if (pcap_setnonblock(p, 1, errbuf) != 0) wifibroadcast::log::get_default()->warn(string_format("set_nonblock failed: %s", errbuf));
  return p;
}

struct RssiForAntenna {
  // which antenna the value refers to,
  // or -1 this dgm value came before a IEEE80211_RADIOTAP_ANTENNA field and the antenna idx is therefore unknown
  const int8_t antennaIdx;
  // https://www.radiotap.org/fields/Antenna%20signal.html
  const int8_t rssi;
};
struct ParsedRxPcapPacket {
  // Size can be anything from size=1 to size== N where N is the number of Antennas of this adapter
  const std::vector<RssiForAntenna> allAntennaValues;
  const Ieee80211HeaderRaw *ieee80211Header;
  const uint8_t *payload;
  const std::size_t payloadSize;
  // Atheros forwards frames even though the fcs check failed ( this packet is corrupted)
  const bool frameFailedFCSCheck;
  // driver might not support that
  std::optional<uint16_t> mcs_index=std::nullopt;
  // driver might not support that
  std::optional<uint16_t> channel_width=std::nullopt;
  std::optional<int> signal_quality=std::nullopt;
};
static std::string all_rssi_to_string(const std::vector<RssiForAntenna>& all_rssi){
  std::stringstream ss;
  ss<<"RSSI for antenna:";
  int idx=0;
  for(const auto& rssiForAntenna:all_rssi){
    ss<<" {"<<(int)rssiForAntenna.antennaIdx<<":"<<(int)rssiForAntenna.rssi<<"}";
    idx++;
  }
  return ss.str();
}
// It looks as if RTL88xxau reports 3 rssi values - for example,
//RssiForAntenna0{10}
//RssiForAntenna1{10}
//RssiForAntenna2{-18}
//Now this doesn't make sense, so this helper should fix it
static std::optional<int8_t> get_best_rssi_of_card(const std::vector<RssiForAntenna>& all_rssi,const bool fixup_rssi_rtl8812au){
  if(all_rssi.empty())return std::nullopt;
  // best rssi == highest value
  int8_t highest_value=INT8_MIN;
  for(int i=0;i<all_rssi.size();i++){
    const auto& rssi_for_antenna=all_rssi[i];
    if(fixup_rssi_rtl8812au || true){
      if(i==0) continue ;
      if(rssi_for_antenna.rssi>highest_value){
        highest_value=rssi_for_antenna.rssi;
      }
    }
  }
  for(const auto& rssiForAntenna:all_rssi){
    if(fixup_rssi_rtl8812au){
      if(rssiForAntenna.antennaIdx==-1){
        continue ;
      }
    }
    if(rssiForAntenna.rssi>highest_value){
      highest_value=rssiForAntenna.rssi;
    }
  }
  return highest_value;
}

// Returns std::nullopt if radiotap was unable to parse the header
// else return the *parsed information*
// To avoid confusion it might help to treat this method as a big black Box :)
static std::optional<ParsedRxPcapPacket> processReceivedPcapPacket(const pcap_pkthdr &hdr, const uint8_t *pkt) {
  int pktlen = hdr.caplen;
  //
  //RadiotapHelper::debugRadiotapHeader(pkt,pktlen);
  // Copy the value of this flag once present and process it after the loop is done
  uint8_t tmpCopyOfIEEE80211_RADIOTAP_FLAGS = 0;
  //RadiotapHelper::debugRadiotapHeader(pkt, pktlen);
  struct ieee80211_radiotap_iterator iterator{};
  // With AR9271 I get 39 as length of the radio-tap header
  // With my internal laptop wifi chip I get 36 as length of the radio-tap header.
  int ret = ieee80211_radiotap_iterator_init(&iterator, (ieee80211_radiotap_header *) pkt, pktlen, NULL);
  // weird, unfortunately it is not really documented / specified how raditap reporting dBm values with multiple antennas works
  // we store all values reported by IEEE80211_RADIOTAP_ANTENNA in here
  // ? there can be multiple ?
  //std::vector<uint8_t> radiotap_antennas;
  // and all values reported by IEEE80211_RADIOTAP_DBM_ANTSIGNAL in here
  //std::vector<int8_t> radiotap_antsignals;
  // for rtl8812au fixup
  bool is_first_reported_antenna_value= true;
  //
  std::optional<uint16_t> mcs_index=std::nullopt;
  std::optional<uint16_t> channel_width=std::nullopt;
  std::optional<int> signal_quality=std::nullopt;

  int8_t currentAntenna = -1;
  // not confirmed yet, but one pcap packet might include stats for multiple antennas
  std::vector<RssiForAntenna> allAntennaValues;
  while (ret == 0) {
    ret = ieee80211_radiotap_iterator_next(&iterator);
    if (ret) {
      continue;
    }
    /* see if this argument is something we can use */
    switch (iterator.this_arg_index) {
      case IEEE80211_RADIOTAP_ANTENNA:
        // RADIOTAP_DBM_ANTSIGNAL seems to come not before, but after
        currentAntenna = iterator.this_arg[0];
        //radiotap_antennas.push_back(iterator.this_arg[0]);
        break;
      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:{
        int8_t value;
        std::memcpy(&value,iterator.this_arg,1);
        allAntennaValues.push_back({currentAntenna,value});
      }
      break;
      case IEEE80211_RADIOTAP_FLAGS:
        tmpCopyOfIEEE80211_RADIOTAP_FLAGS = *(uint8_t *) (iterator.this_arg);
        break;
      case IEEE80211_RADIOTAP_MCS:
      {
        uint8_t known = iterator.this_arg[0];
        uint8_t flags = iterator.this_arg[1];
        uint8_t mcs = iterator.this_arg[2];
        if(known & IEEE80211_RADIOTAP_MCS_HAVE_MCS){
          mcs_index=static_cast<uint16_t>(mcs);
        }
        if (known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
          const uint8_t bandwidth = flags & IEEE80211_RADIOTAP_MCS_BW_MASK;
          switch (bandwidth) {
            case IEEE80211_RADIOTAP_MCS_BW_20:
            case IEEE80211_RADIOTAP_MCS_BW_20U:
            case IEEE80211_RADIOTAP_MCS_BW_20L:
              channel_width=static_cast<uint16_t>(20);
              break;
            case IEEE80211_RADIOTAP_MCS_BW_40:
              channel_width=static_cast<uint16_t>(40);
              break;
            default:
              break ;
          }
        }
      }
      break;
      case IEEE80211_RADIOTAP_LOCK_QUALITY:{
        int8_t value;
        std::memcpy(&value,iterator.this_arg,1);
        signal_quality=static_cast<int>(value);
      } break ;
      default:break;
    }
  }  /* while more rt headers */
  if (ret != -ENOENT) {
    //wifibroadcast::log::get_default()->warn("Error parsing radiotap header!\n";
    return std::nullopt;
  }
  bool frameFailedFcsCheck = false;
  if (tmpCopyOfIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_BADFCS) {
    //wifibroadcast::log::get_default()->warn("Got packet with bad fsc\n";
    frameFailedFcsCheck = true;
  }
  // the fcs is at the end of the packet
  if (tmpCopyOfIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_FCS) {
    //<<"Packet has IEEE80211_RADIOTAP_F_FCS";
    pktlen -= 4;
  }
#ifdef ENABLE_ADVANCED_DEBUGGING
  wifibroadcast::log::get_default()->debug(RadiotapFlagsToString::flagsIEEE80211_RADIOTAP_MCS(mIEEE80211_RADIOTAP_MCS));
  wifibroadcast::log::get_default()->debug(RadiotapFlagsToString::flagsIEEE80211_RADIOTAP_FLAGS(mIEEE80211_RADIOTAP_FLAGS));
  // With AR9271 I get 39 as length of the radio-tap header
  // With my internal laptop wifi chip I get 36 as length of the radio-tap header
  wifibroadcast::log::get_default()->debug("iterator._max_length was {}",iterator._max_length);
#endif
  //assert(iterator._max_length==hdr.caplen);
  /* discard the radiotap header part */
  pkt += iterator._max_length;
  pktlen -= iterator._max_length;
  //
  const Ieee80211HeaderRaw *ieee80211Header = (Ieee80211HeaderRaw *) pkt;
  const uint8_t *payload = pkt + Ieee80211HeaderRaw::SIZE_BYTES;
  const std::size_t payloadSize = (std::size_t) pktlen - Ieee80211HeaderRaw::SIZE_BYTES;
  //
  /*std::stringstream ss;
  ss<<"Antennas:";
  for(const auto& antenna : radiotap_antennas){
    ss<<(int)antenna<<",";
  }
  ss<<"\nAntsignals:";
  for(const auto& antsignal : radiotap_antsignals){
    ss<<(int)antsignal<<",";
  }
  std::cout<<ss.str();*/
  return ParsedRxPcapPacket{allAntennaValues, ieee80211Header, payload, payloadSize, frameFailedFcsCheck,mcs_index,channel_width,signal_quality};
}

// [RadiotapHeader | Ieee80211HeaderRaw | customHeader (if not size 0) | payload (if not size 0)]
static std::vector<uint8_t> create_radiotap_wifi_packet(const RadiotapHeader& radiotapHeader,
                                                        const Ieee80211HeaderRaw &ieee80211Header,
                                                        const uint8_t* data,int data_len){
  std::vector<uint8_t> packet(radiotapHeader.getSize() + sizeof(ieee80211Header.data) + data_len);
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

}

#endif  // WIFIBROADCAST_SRC_PCAP_HELPER_H_
