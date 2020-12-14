// -*- C++ -*-
//
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>

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

#include <unordered_map>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <errno.h>
#include <string>
#include <string.h>
#include "wifibroadcast.hpp"
#include <stdexcept>
#include "Encryption.hpp"
#include "FEC.hpp"
#include "Helper.hpp"
#include "OpenHDStatisticsWriter.hpp"
#include "HelperSources/TimeHelper.hpp"

static constexpr const auto RX_ANT_MAX=4;
class antennaItem {
public:
    antennaItem()=default;

    void addRSSI(int8_t rssi) {
        if (count_all == 0) {
            rssi_min = rssi;
            rssi_max = rssi;
        } else {
            rssi_min = std::min(rssi, rssi_min);
            rssi_max = std::max(rssi, rssi_max);
        }
        rssi_sum += rssi;
        count_all += 1;
    }

    int32_t count_all=0;
    int32_t rssi_sum=0;
    int8_t rssi_min=0;
    int8_t rssi_max=0;
};

typedef std::unordered_map<uint64_t, antennaItem> antenna_stat_t;

// This class processes the received wifi data (decryption and FEC)
// and forwards it via UDP.
class Aggregator :  public FECDecoder {
public:
    Aggregator(const std::string &client_addr, int client_udp_port,uint8_t radio_port, int k, int n, const std::string &keypair);

    ~Aggregator();

    void
    processPacket(uint8_t wlan_idx,const pcap_pkthdr& hdr,const uint8_t* pkt);

    void dump_stats(FILE *fp) ;
    // the port data is forwarded to
    const int CLIENT_UDP_PORT;
    // do not pass data from the receiver to the Aggregator where radio port doesn't match
    const uint8_t RADIO_PORT;
private:
    void sendPacketViaUDP(const uint8_t *packet,std::size_t packetSize) const{
        send(sockfd,packet,packetSize, MSG_DONTWAIT);
    }
    const std::chrono::steady_clock::time_point INIT_TIME=std::chrono::steady_clock::now();
    Decryptor mDecryptor;
    int sockfd;
    antenna_stat_t antenna_stat;
    uint32_t count_p_all=0;
    uint32_t count_p_bad=0;
    uint32_t count_p_dec_err=0;
    uint32_t count_p_dec_ok=0;
    OpenHDStatisticsWriter openHdStatisticsWriter{RADIO_PORT};
    OpenHDStatisticsWriter::Data statistics{};
private:
#ifdef ENABLE_ADVANCED_DEBUGGING
    // time between <packet arrives at pcap processing queue> <<->> <packet is pulled out of pcap by RX>
    AvgCalculator avgPcapToApplicationLatency;
    AvgCalculator2 avgLatencyBeaconPacketLatency;
#endif
};

// This class listens for WIFI data on the specified wlan for wifi packets with the right RADIO_PORT
// Processing of data is done by the Aggregator
class PcapReceiver {
public:
    PcapReceiver(const std::string& wlan, int wlan_idx, int radio_port, Aggregator *agg);

    ~PcapReceiver();

    void loop_iter();

    void xLoop();

    int getfd() const { return fd; }

public:
    // the wifi interface this receiver listens on
    const int WLAN_IDX;
    // the radio port it filters pacp packets for
    const int RADIO_PORT;
    // processes received packets
public:
    Aggregator* agg;
    // this fd is created by pcap
    int fd;
    pcap_t *ppcap;
};

