// Copyright (C) 2017, 2018, 2019 Vasily Evseenko <svpcom@p2ptech.org>

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


#ifndef __WIFIBROADCAST_HPP__
#define __WIFIBROADCAST_HPP__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <endian.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sodium.h>
#include <endian.h>
#include <string>
#include <vector>
#include <chrono>
#include <optional>

extern "C"{
#include "ExternalCSources/radiotap.h"
};
#include "Ieee80211Header.hpp"
#include "RadiotapHeader.hpp"

/**
 * Wifibroadcast protocol:
 * radiotap_header
 * * ieee_80211_header
 * ** if WFB_PACKET_KEY
 * *** WBSessionKeyPacket
 * ** if WFB_PACKET_DATA
 * *** WBDataHeader
 * **** encrypted payload data (dynamic size)
 */

static constexpr const uint8_t WFB_PACKET_DATA=0x1;
static constexpr const uint8_t WFB_PACKET_KEY=0x2;
// for testing, do not use in production (just don't send it on the tx)
static constexpr const uint8_t WFB_PACKET_LATENCY_BEACON=0x3;

// the encryption key is sent every n seconds ( but not re-created every n seconds, it is only re-created when reaching the max sequence number)
// also it is only sent if a new packet needs to be transmitted to save bandwidth
// it needs to be sent multiple times instead of once since it might get lost on the first or nth time respective
static constexpr const auto SESSION_KEY_ANNOUNCE_DELTA=std::chrono::seconds(1);


// Session key packet
// Since the size of each session key packet never changes, this memory layout is the easiest
class WBSessionKeyPacket{
public:
    // note how this member doesn't add up to the size of this class (c++ is so great !)
    static constexpr auto SIZE_BYTES=(sizeof(uint8_t)+crypto_box_NONCEBYTES+crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES);
public:
    const uint8_t packet_type=WFB_PACKET_KEY;
    uint8_t session_key_nonce[crypto_box_NONCEBYTES];  // random data
    uint8_t session_key_data[crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES]; // encrypted session key
}__attribute__ ((packed));
static_assert(sizeof(WBSessionKeyPacket) == WBSessionKeyPacket::SIZE_BYTES, "ALWAYS_TRUE");


// This header comes with each FEC packet (primary or secondary)
// This part is not encrypted !
class WBDataHeader{
public:
    // nonce:  56bit block_idx + 8bit fragment_idx
    static constexpr auto BLOCK_IDX_MASK=((1LLU << 56) - 1);
    static constexpr uint64_t MAX_BLOCK_IDX=((1LLU << 55) - 1);
    // conversion from / to nonce
    static uint64_t calculateNonce(const uint64_t block_idx,const uint8_t fragment_idx){
        assert(block_idx<=MAX_BLOCK_IDX); // should never happen
        return htobe64(((block_idx & BLOCK_IDX_MASK) << 8) + fragment_idx);
    }
    static uint64_t calculateBlockIdx(const uint64_t nonce){
        return be64toh(nonce) >> 8;
    }
    static uint8_t calculateFragmentIdx(const uint64_t nonce){
        return (uint8_t) (be64toh(nonce) & 0xff);
    }
    explicit WBDataHeader(uint64_t nonce1):nonce(nonce1){};
    uint8_t getFragmentIdx()const{
        return calculateFragmentIdx(nonce);
    }
    uint64_t getBlockIdx()const{
        return calculateBlockIdx(nonce);
    }
public:
    const uint8_t packet_type=WFB_PACKET_DATA;
    const uint64_t nonce;  // big endian, nonce = block_idx << 8 + fragment_idx
}  __attribute__ ((packed));
static_assert(sizeof(WBDataHeader)==8+1,"ALWAYS_TRUE");


// this header is written before the data of each primary FEC fragment
// ONLY for primary FEC fragments though ! (up to n bytes workaround)
class FECDataHeader {
private:
    // private member to make sure it has always the right endian
    uint16_t packet_size; // big endian
public:
    explicit FECDataHeader(std::size_t packetSize1){
        // convert to big endian if needed
        packet_size=htobe16(packetSize1);
    }
    // convert from big endian if needed
    std::size_t get()const{
        return be16toh(packet_size);
    }
}  __attribute__ ((packed));
static_assert(sizeof(FECDataHeader) == 2, "ALWAYS_TRUE");

// This one does not specify if it is an FEC data or FEC correction packet (see WBDataHeader / FECDataHeader)
// but it is always of type WFB_PACKET_DATA
// NOTE: This cannot be casted directly from / to a memory location (unlike the classes above) since the payload size is dynamic
// Use the constructor(s) or use the createFromRawMemory() method
class WBDataPacket{
public:
    // construct in c-style (light),used on TX
    WBDataPacket(const uint64_t nonce1,const uint8_t* payload1,const std::size_t payloadSize1):
            wbDataHeader(nonce1), payload(payload1), payloadSize(payloadSize1){};
    // construct in c++-style (just as light,too),used on TX
    WBDataPacket(const uint64_t nonce1,const std::shared_ptr<std::vector<uint8_t>>& payload1):
            wbDataHeader(nonce1), payload(payload1->data()), payloadSize(payload1->size()), optionalPayloadDataReference(payload1){};
    // to re-interpret on the RX
    static WBDataPacket createFromRawMemory(const uint8_t* data,std::size_t dataSize){
        assert(data[0]==WFB_PACKET_DATA);
        const WBDataHeader* wbDataHeader=(WBDataHeader*)data;
        return {wbDataHeader->nonce,&data[sizeof(WBDataHeader)],dataSize-sizeof(WBDataHeader)};
    }
    // don't allow copying or moving, since creating a new one is light enough
    //WBDataPacket(const WBDataPacket&)=delete;
    //WBDataPacket(const WBDataPacket&&)=delete;
public:
    // each data packet has the WBDataHeader
    const WBDataHeader wbDataHeader;
    // If this is an FEC data packet, first two bytes of payload are the FECDataHeader
    // If this is an FEC correction packet, that's not the case
    // Use the "Encryptor" class to encrypt / decrypt the payload
    const uint8_t* payload;
    const std::size_t payloadSize;
    // this one is for the c++-constructor only
    const std::shared_ptr<std::vector<uint8_t>> optionalPayloadDataReference=nullptr;
};


struct LatencyTestingPacket{
    const uint8_t packet_type=WFB_PACKET_LATENCY_BEACON;
    const int64_t timestampNs=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}__attribute__ ((packed));

// The final packet size ( radiotap header + iee80211 header + payload ) is never bigger than that
// the reasoning behind this value: https://github.com/svpcom/wifibroadcast/issues/69
static constexpr const auto MAX_PCAP_PACKET_SIZE=1510;
// Max n of wifi cards connected as an RX array
static constexpr const auto MAX_RX_INTERFACES=8;

// 1510-(13+24+9+16+2)
//A: Any UDP with packet size <= 1466. For example x264 inside RTP or Mavlink.
static constexpr const auto MAX_PAYLOAD_SIZE=(MAX_PCAP_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES - sizeof(WBDataHeader) - crypto_aead_chacha20poly1305_ABYTES - sizeof(FECDataHeader));
static constexpr const auto MAX_FEC_PAYLOAD=(MAX_PCAP_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES - sizeof(WBDataHeader) - crypto_aead_chacha20poly1305_ABYTES);
static constexpr const auto MAX_FORWARDER_PACKET_SIZE=(MAX_PCAP_PACKET_SIZE - RadiotapHeader::SIZE_BYTES - Ieee80211Header::SIZE_BYTES);

// comment this for a release
//#define ENABLE_ADVANCED_DEBUGGING

#endif //__WIFIBROADCAST_HPP__
