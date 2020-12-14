//
// Created by consti10 on 06.12.20.
//

#ifndef WIFIBROADCAST_OPENHDSTATISTICSWRITER_H
#define WIFIBROADCAST_OPENHDSTATISTICSWRITER_H

#include <stdint.h>

// TODO what happens here has to be decided yet
// write the fec decoding stats (and optionally RSSI ) for each rx stream

class OpenHDStatisticsWriter{
public:
    // the unique stream ID this processes statistics for
    const uint8_t RADIO_PORT;
    // Forwarded data
    struct Data{
        // all these values are absolute (like done previously in OpenHD)
        // all received packets
        uint64_t count_p_all=0;
        // n packets that were received but could not be used (after already filtering for the right port)
        uint64_t count_p_bad=0;
        // n packets that could not be decrypted
        uint64_t count_p_dec_err=0;
        // n packets that were successfully decrypted
        uint64_t count_p_dec_ok=0;
        // n packets that were corrected by FEC
        uint64_t count_p_fec_recovered=0;
        // n packets that were completely lost though FEC
        uint64_t count_p_lost=0;
        // TODO the rssi stuff ( a bit complicated)
        // since multiple RX are listening on the same wifi card
    };
    void writeStats(const Data& data){
        // Perhaps RADIO_PORT==0 means video and so on
        // TODO write to udp port or shared memory or ...
    }
};

#endif //WIFIBROADCAST_OPENHDSTATISTICSWRITER_H
