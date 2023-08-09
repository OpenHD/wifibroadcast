#ifndef __WIFIBROADCAST_IEEE80211_HEADER_HPP__
#define __WIFIBROADCAST_IEEE80211_HEADER_HPP__

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <resolv.h>
#include <cstring>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <endian.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <endian.h>
#include <string>
#include <vector>
#include <array>
#include <iostream>

// Helper for dealing with the IEEE80211 header in wifibroadcast / openhd
// Usefully references:
// https://witestlab.poly.edu/blog/802-11-wireless-lan-2/
// https://en.wikipedia.org/wiki/802.11_Frame_Types
// https://elixir.bootlin.com/linux/latest/source/include/linux/ieee80211.h

// NOTE: THIS IS THE LAYOUT OF A NORMAL IEEE80211 header
// | 2 bytes       | 2 bytes  | 6 bytes   | 6 bytes | 6 bytes | 2 bytes          |
// | control field | duration | MAC of AP | SRC MAC | DST MAC | Sequence control |
static constexpr auto IEEE80211_HEADER_SIZE_BYTES = 24;

// Helper for control field - we do not touch it
struct ControlField{
  uint8_t part1=0x08;
  uint8_t part2=0x01;
}__attribute__ ((packed));
static_assert(sizeof(ControlField) == 2);

// Helper for sequence control field
//https://witestlab.poly.edu/blog/802-11-wireless-lan-2/
//Sequence Control: Contains a 4-bit fragment number subfield, used for fragmentation and reassembly, and a 12-bit sequence number used to number
//frames sent between a given transmitter and receiver.
struct SequenceControl {
  uint8_t subfield: 4;
  uint16_t sequence_nr: 12;
  std::string as_debug_string()const{
    std::stringstream ss;
    ss << "SequenceControl["<<"" << (int)subfield << ":" << (int) sequence_nr<<"]";
    return ss.str();
  }
}__attribute__ ((packed));
static_assert(sizeof(SequenceControl) == 2);

// We use as many bytes of this header for useful purposes as possible - might be a bit hard to understand for beginners why we use stuff this way,
// but optimizing on a byte level is complicated and we have to account for driver quirks

static constexpr auto OPENHD_IEEE80211_HEADER_UNIQUE_ID_AIR=0x01;
static constexpr auto OPENHD_IEEE80211_HEADER_UNIQUE_ID_GND=0x02;

struct Ieee80211HeaderOpenHD{
  // We do not touch the control field (driver)
  //ControlField control_field{};
  uint8_t control_field_part1=0x08;
  uint8_t control_field_part2=0x01;
  // We do not touch the duration field (driver)
  uint8_t duration1=0x00;
  uint8_t duration2=0x00;
  // We do not touch this MAC (driver) - and set it to broadcast such that the monitor mode driver accepts it
  std::array<uint8_t, 6> mac_ap={0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  // We can and do use this mac - 1 byte for unique identifier (air/gnd), 4 bytes for part 1 of nonce, last byte for radio port
  uint8_t mac_src_unique_id_part=OPENHD_IEEE80211_HEADER_UNIQUE_ID_AIR;
  std::array<uint8_t, 4> mac_src_nonce_part1={};
  uint8_t mac_src_radio_port=0;
  // We can and do use this mac - 1 byte for unique identifier (air/gnd), 4 bytes for part 2 of nonce, last byte for radio port
  uint8_t mac_dst_unique_id_part=OPENHD_IEEE80211_HEADER_UNIQUE_ID_AIR;
  std::array<uint8_t, 4> mac_dst_nonce_part2={};
  uint8_t mac_dst_radio_port=0;
  // iee80211 sequence control ( 2 bytes ) - might be overridden by the driver, and/or even repurposed
  uint16_t sequence_control=0;
  // ----------------------------------- DATA LAYOUT END -----------------------------------
  /**
   * We use some of the available bytes for a 8 bytes "nonce"
   */
  void write_nonce(const uint64_t nonce){
    memcpy((uint8_t*)&mac_src_nonce_part1,(uint8_t*)&nonce,4);
    memcpy((uint8_t*)&mac_dst_nonce_part2,((uint8_t*)&nonce)+4,4);
    // From https://stackoverflow.com/questions/2810280/how-to-store-a-64-bit-integer-in-two-32-bit-integers-and-convert-back-again
    //mac_src_nonce_part1 = static_cast<int32_t>(nonce >> 32);
    //mac_dst_nonce_part2 = static_cast<int32_t>(nonce);
  }
  uint64_t get_nonce()const{
    uint64_t nonce=0;
    memcpy(((uint8_t*)&nonce),(uint8_t*)&mac_src_nonce_part1,4);
    memcpy(((uint8_t*)&nonce)+4,(uint8_t*)&mac_dst_nonce_part2,4);
    return nonce;
  }
  /**
   * NOTE: We write the radio port 2 times - this way we have a pretty reliable way to check if this is an openhd packet or packet from someone else
   */
  void write_radio_port_src_dst(uint8_t radio_port){
    mac_src_radio_port=radio_port;
    mac_dst_radio_port=radio_port;
  }
  /*
   *  We also write the unique id 2 times - same reason like with radio port
   */
  void write_unique_id_src_dst(uint8_t id){
    mac_src_unique_id_part=id;
    mac_dst_unique_id_part=id;
  }
  // Check - first byte of scr and dst mac needs to mach (unique air / gnd id)
  bool has_valid_air_gnd_id()const{
    return mac_src_unique_id_part==mac_dst_unique_id_part;
  }
  // Check - last byte of src and dst mac needs to match (radio port)
  bool has_valid_radio_port()const{
    return mac_src_radio_port==mac_dst_radio_port;
  }
  // validate before use (matching)
  uint8_t get_valid_air_gnd_id()const{
    return mac_src_unique_id_part;
  }
  // validate before use (matching)
  uint8_t get_valid_radio_port()const{
    return mac_src_radio_port;
  }
  bool is_data_frame() const {
    return control_field_part1 == 0x08 && control_field_part2 == 0x01;
  }
  std::string debug_radio_ports()const{
    return fmt::format("{}:{}",(int)mac_src_radio_port,(int)mac_dst_radio_port);
  }
  std::string debug_unique_ids()const{
    return fmt::format("{}:{}",(int)mac_src_unique_id_part,(int)mac_dst_unique_id_part);
  }
  std::string debug_control_field()const{
    return fmt::format("{}:{}",StringHelper::byte_as_hex(control_field_part1),StringHelper::byte_as_hex(control_field_part2));
  }
  // Only for testing !
  void dirty_write_dummy_fixed_src_dest_mac(){
    uint8_t* src_mac=&mac_src_unique_id_part;
    uint8_t* dst_mac=&mac_dst_unique_id_part;
    static constexpr std::array<uint8_t, 6> dummy_mac1={0x00, 0x00, 0x01, 0x01, 0x02, 0x02};
    static constexpr std::array<uint8_t, 6> dummy_mac2={0x02, 0x02, 0x01, 0x01, 0x00, 0x00};
    memcpy(src_mac,dummy_mac1.data(),6);
    memcpy(dst_mac,dummy_mac2.data(),6);
  }
  // Dirty
  void write_ieee80211_seq_nr(const uint16_t seq_nr){
    uint8_t seq_nr_buf[2];
    seq_nr_buf[0] = seq_nr & 0xff;
    seq_nr_buf[1] = (seq_nr >> 8) & 0xff;
    memcpy((uint8_t*)&sequence_control,seq_nr_buf,2);
  }
}__attribute__ ((packed));
static_assert(sizeof(Ieee80211HeaderOpenHD)==IEEE80211_HEADER_SIZE_BYTES);


// Wrapper around the Ieee80211 header (declared as raw array initially)
// info https://witestlab.poly.edu/blog/802-11-wireless-lan-2/
// In the way this is declared it is an IEE80211 data frame
// https://en.wikipedia.org/wiki/802.11_Frame_Types
//TODO maybe use https://elixir.bootlin.com/linux/latest/source/include/linux/ieee80211.h
class Ieee80211HeaderRaw {
 public:
  static constexpr auto SIZE_BYTES = 24;
  //the last byte of the mac address is recycled as a port number
  static constexpr const auto SRC_MAC_LASTBYTE = 15;
  static constexpr const auto DST_MAC_LASTBYTE = 21;
  static constexpr const auto FRAME_SEQ_LB = 22;
  static constexpr const auto FRAME_SEQ_HB = 23;
  // raw data buffer
  std::array<uint8_t, SIZE_BYTES> data = {
      0x08, 0x01, // first 2 bytes control fiels
      0x00, 0x00, // 2 bytes duration (has this even an effect ?!)
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // something MAC ( 6 bytes), I think Receiver address (MAC of AP)
      0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // something MAC ( 6 bytes), I think SRC MAC  (mac of source STA)- last byte is used as radio port
      0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // something MAC ( 6 bytes), I think DEST MAC (mac of dest STA)  - last byte is als used as radio port
      0x00, 0x00,  // iee80211 sequence control ( 2 bytes )
  };
  // default constructor
  Ieee80211HeaderRaw() = default;
  /*static std::string mac_as_string(const uint8_t* mac_6bytes){
    return StringHelper::bytes_as_string_hex(mac_6bytes,6);
  }
  std::string header_as_string()const{
    std::stringstream ss;
    ss<<sequence_control_as_string()<<"\n";
    ss<<"mac"<<mac_as_string(&data[4])<<"\n";
    ss<<"src_mac"<<mac_as_string(&data[4+6])<<"\n";
    ss<<"dst_mac"<<mac_as_string(&data[4+6])<<"\n";
    return ss.str();
  }*/
}__attribute__ ((packed));
static_assert(sizeof(Ieee80211HeaderRaw) == Ieee80211HeaderRaw::SIZE_BYTES, "ALWAYS TRUE");

namespace Ieee80211ControllFrames {
static uint8_t u8aIeeeHeader_rts[] = {
    0xb4, 0x01, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
    0xff                    // 1st byte of MAC will be overwritten with encoded port
};
}

// hmmmm ....
// https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_rawsock.c#L175
// https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_telemetry.c#L144
namespace OldWifibroadcastIeee8021Header {
static uint8_t u8aIeeeHeader_data[] = {
    0x08, 0x02, 0x00, 0x00,             // frame control field (2 bytes), duration (2 bytes)
    0xff, 0x00, 0x00, 0x00, 0x00, 0x00, // 1st byte of MAC will be overwritten with encoded port
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
    0x00, 0x00                          // IEEE802.11 seqnum, (will be overwritten later by Atheros firmware/wifi chip)
};
// I think this is actually this type of frame
// https://en.wikipedia.org/wiki/Block_acknowledgement
// has only 64*16=1024 bits payload
static uint8_t u8aIeeeHeader_data_short[] = {
    0x08, 0x01, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
    0xff                    // 1st byte of MAC will be overwritten with encoded port
};
// I think this is this type of frame 01 Control 1011 RTS
// https://en.wikipedia.org/wiki/IEEE_802.11_RTS/CTS
// however, rts frames usually don't have a payload
static uint8_t u8aIeeeHeader_rts[] = {
    0xb4, 0x01, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
    0xff                    // 1st byte of MAC will be overwritten with encoded port
};
}

namespace test{
static void test_nonce(){
  Ieee80211HeaderOpenHD tmp{};
  assert(tmp.is_data_frame());
  for(uint64_t nonce=0;nonce<10;nonce++){
    tmp.write_nonce(nonce);
    assert(tmp.get_nonce()==nonce);
  }
  const auto nonce_high=UINT64_MAX-100;
  for(uint64_t nonce=nonce_high;nonce<nonce_high+20;nonce++){
    tmp.write_nonce(nonce);
    assert(tmp.get_nonce()==nonce);
  }
}
static void test_sequence_number(){

}

}

// Everything in here assumes little endian
static_assert(__BYTE_ORDER == __LITTLE_ENDIAN, "This code is written for little endian only !");
#endif