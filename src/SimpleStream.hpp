//
// Created by consti10 on 10.03.21.
//

#ifndef WIFIBROADCAST_SIMPLESTREAM_HPP
#define WIFIBROADCAST_SIMPLESTREAM_HPP

#include <cstdint>
#include <cerrno>
#include <string>
#include <utility>
#include <vector>
#include <array>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <functional>
#include <map>
#include <limits>
#include <cassert>

// FEC Disabled is used for telemetry data in OpenHD.
// We have different requirements on packet loss and/or packet reordering for this type of data stream.
// Adds sizeof(FECDisabledHeader) overhead
// received packets are quaranteed to be forwarded with the following properties:
// No doplicates
// packets out of order are possible

struct FECDisabledHeader{
  // rolling sequence number
  uint64_t sequence_number;
}__attribute__ ((packed));
static_assert(sizeof(FECDisabledHeader)==8);

// Really simple, adds a sequence number, nothing else
class FECDisabledEncoder {
 public:
  typedef std::function<void(const uint8_t *payload, const std::size_t payloadSize)>
      OUTPUT_DATA_CALLBACK;
  OUTPUT_DATA_CALLBACK outputDataCallback;
  std::vector<uint8_t> encode_packet_buffer(const uint8_t *buf, const size_t size){
    std::vector<uint8_t> tmp(size+sizeof(FECDisabledHeader));
    FECDisabledHeader hdr{};
    hdr.sequence_number=currPacketIndex;
    // copy the header
    memcpy(tmp.data(),(uint8_t*)&hdr,sizeof(FECDisabledHeader));
    // copy the payload
    memcpy(tmp.data()+sizeof(FECDisabledHeader),buf,size);
    currPacketIndex++;
    if (currPacketIndex == std::numeric_limits<uint64_t>::max()) {
      currPacketIndex = 0;
    }
    return tmp;
  }
  // encodes a packet and then forwards it via the cb
  void encode_packet_cb(const uint8_t *buf, const size_t size) {
    const auto packet= encode_packet_buffer(buf,size);
    outputDataCallback(packet.data(),packet.size());
  }
 private:
  uint64_t currPacketIndex = 0;
};

class FECDisabledDecoder {
 public:
  typedef std::function<void(const uint8_t *payload, std::size_t payloadSize)> SEND_DECODED_PACKET;
  // WARNING: Don't forget to register this callback !
  SEND_DECODED_PACKET mSendDecodedPayloadCallback;
 private:
  // Add a limit here to not allocate infinite amounts of memory
  static constexpr std::size_t FEC_DISABLED_MAX_SIZE_OF_MAP = 100;
  std::map<uint64_t, void *> m_known_sequence_numbers;
  bool first_ever_packet = true;
 public:
  void process_packet(const uint8_t* data,int len){
    if(len<sizeof(FECDisabledHeader)+1){
      // not a valid packet
      return ;
    }
    auto* hdr=(FECDisabledHeader*)data;
    const uint8_t* payload=data+sizeof(FECDisabledHeader);
    const auto payload_size=len-sizeof(FECDisabledHeader);
    process_packet_seq_nr_and_payload(hdr->sequence_number,payload,payload_size);
  }
  //No duplicates, but packets out of order are possible
  //counting lost packets doesn't work in this mode. It should be done by the upper level
  //saves the last FEC_DISABLED_MAX_SIZE_OF_MAP sequence numbers. If the sequence number of a new packet is already inside the map, it is discarded (duplicate)
  void process_packet_seq_nr_and_payload(uint64_t packetSeq,const uint8_t* payload,std::size_t payload_len){
    assert(mSendDecodedPayloadCallback);
    if (first_ever_packet) {
      // first ever packet. Map should be empty
      m_known_sequence_numbers.clear();
      mSendDecodedPayloadCallback(payload,payload_len);
      m_known_sequence_numbers.insert({packetSeq, nullptr});
      first_ever_packet = false;
    }
    // check if packet is already known (inside the map)
    const auto search = m_known_sequence_numbers.find(packetSeq);
    if (search == m_known_sequence_numbers.end()) {
      // if packet is not in the map it was not yet received(unless it is older than MAX_SIZE_OF_MAP, but that is basically impossible)
      mSendDecodedPayloadCallback(payload,payload_len);
      m_known_sequence_numbers.insert({packetSeq, nullptr});
    }// else this is a duplicate
    // house keeping, do not increase size to infinity
    if (m_known_sequence_numbers.size() >= FEC_DISABLED_MAX_SIZE_OF_MAP - 1) {
      // remove oldest element
      m_known_sequence_numbers.erase(m_known_sequence_numbers.begin());
    }
  }
};

#endif  // WIFIBROADCAST_SIMPLESTREAM_HPP
