#ifndef __WIFIBROADCAST_IEEE80211_HEADER_HPP__
#define __WIFIBROADCAST_IEEE80211_HEADER_HPP__

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

// Wrapper around the Ieee80211 header (declared as raw array initially)
// info https://witestlab.poly.edu/blog/802-11-wireless-lan-2/
// In the way this is declared it is an IEE80211 data frame
// https://en.wikipedia.org/wiki/802.11_Frame_Types
class Ieee80211Header{
public:
    static constexpr auto SIZE_BYTES=24;
    //the last byte of the mac address is recycled as a port number
    static constexpr const auto SRC_MAC_LASTBYTE=15;
    static constexpr const auto DST_MAC_LASTBYTE=21;
    static constexpr const auto FRAME_SEQ_LB=22;
    static constexpr const auto FRAME_SEQ_HB=23;
    // raw data buffer
    std::array<uint8_t,SIZE_BYTES> data={
            0x08, 0x01, // first 2 bytes controll fiels
            0x00, 0x00, // 2 bytes duration (has this even an effect ?!)
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // something MAC ( 6 bytes)
            0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // something MAC ( 6 bytes)
            0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // something MAC ( 6 bytes)
            0x00, 0x00,  // iee80211 sequence number ( 2 bytes )
    };
    // default constructor
    Ieee80211Header()=default;
    // write the port re-using the MAC address (which is unused for broadcast)
    // write sequence number (not used on rx right now)
    void writeParams(const uint8_t radioPort,const uint16_t seqenceNumber){
        data[SRC_MAC_LASTBYTE] = radioPort;
        data[DST_MAC_LASTBYTE] = radioPort;
        data[FRAME_SEQ_LB] = seqenceNumber & 0xff;
        data[FRAME_SEQ_HB] = (seqenceNumber >> 8) & 0xff;
    }
    uint8_t getRadioPort()const{
        return data[SRC_MAC_LASTBYTE];
    }
    uint16_t getSequenceNumber()const{
        uint16_t ret;
        memcpy(&ret,&data[FRAME_SEQ_LB],sizeof(uint16_t));
        return ret;
    }
    const uint8_t* getData()const{
        return data.data();
    }
    constexpr std::size_t getSize()const{
        return data.size();
    }
    uint16_t getFrameControl()const{
        uint16_t ret;
        memcpy(&ret,&data[0],2);
        return ret;
    }
    uint16_t getDurationOrConnectionId()const{
        uint16_t ret;
        memcpy(&ret,&data[2],2);
        return ret;
    }
}__attribute__ ((packed));
static_assert(sizeof(Ieee80211Header) == Ieee80211Header::SIZE_BYTES, "ALWAYS TRUE");

// hmmmm ....
// https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_rawsock.c#L175
// https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_telemetry.c#L144
namespace OldWifibroadcastIeee8021Header{
    static uint8_t u8aIeeeHeader_data[] = {
            0x08, 0x02, 0x00, 0x00,             // frame control field (2 bytes), duration (2 bytes)
            0xff, 0x00, 0x00, 0x00, 0x00, 0x00, // 1st byte of MAC will be overwritten with encoded port
            0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
            0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
            0x00, 0x00                          // IEEE802.11 seqnum, (will be overwritten later by Atheros firmware/wifi chip)
    };


    static uint8_t u8aIeeeHeader_data_short[] = {
            0x08, 0x01, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
            0xff                    // 1st byte of MAC will be overwritten with encoded port
    };


    static uint8_t u8aIeeeHeader_rts[] = {
            0xb4, 0x01, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
            0xff                    // 1st byte of MAC will be overwritten with encoded port
    };
}
#endif