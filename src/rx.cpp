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

#include <assert.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#include <memory>
#include <string>
#include <memory>
#include <chrono>
#include <sstream>

#include "wifibroadcast.hpp"
#include "rx.hpp"
extern "C"{
#include "ExternalCSources/fec.h"
#include "ExternalCSources/radiotap_iter.h"
}

namespace RawTransmitterHelper{
    // call before pcap_activate
    static void iteratePcapTimestamps(pcap_t* ppcap){
        int* availableTimestamps;
        const int nTypes=pcap_list_tstamp_types(ppcap,&availableTimestamps);
        std::cout<<"N available timestamp types "<<nTypes<<"\n";
        for(int i=0;i<nTypes;i++){
            const char* name=pcap_tstamp_type_val_to_name(availableTimestamps[i]);
            const char* description=pcap_tstamp_type_val_to_description(availableTimestamps[i]);
            std::cout<<"Name: "<<std::string(name)<<" Description: "<<std::string(description)<<"\n";
            if(availableTimestamps[i]==PCAP_TSTAMP_HOST){
                std::cout<<"Setting timestamp to host\n";
                pcap_set_tstamp_type(ppcap,PCAP_TSTAMP_HOST);
            }
        }
        pcap_free_tstamp_types(availableTimestamps);
    }
    // copy paste from svpcom
    // I think this one opens the rx interface with pcap and then sets a filter such that only packets pass through for the selected radio port
    static pcap_t* openRxWithPcap(const std::string& wlan,const int radio_port){
        pcap_t* ppcap;
        char errbuf[PCAP_ERRBUF_SIZE];
        ppcap = pcap_create(wlan.c_str(), errbuf);
        if (ppcap == NULL) {
            throw std::runtime_error(StringFormat::convert("Unable to open interface %s in pcap: %s", wlan.c_str(), errbuf));
        }
        iteratePcapTimestamps(ppcap);
        if (pcap_set_snaplen(ppcap, 4096) != 0) throw std::runtime_error("set_snaplen failed");
        if (pcap_set_promisc(ppcap, 1) != 0) throw std::runtime_error("set_promisc failed");
        //if (pcap_set_rfmon(ppcap, 1) !=0) throw runtime_error("set_rfmon failed");
        if (pcap_set_timeout(ppcap, -1) != 0) throw std::runtime_error("set_timeout failed");
        //if (pcap_set_buffer_size(ppcap, 2048) !=0) throw runtime_error("set_buffer_size failed");
        if (pcap_activate(ppcap) != 0) throw std::runtime_error(StringFormat::convert("pcap_activate failed: %s", pcap_geterr(ppcap)));
        if (pcap_setnonblock(ppcap, 1, errbuf) != 0) throw std::runtime_error(StringFormat::convert("set_nonblock failed: %s", errbuf));

        int link_encap = pcap_datalink(ppcap);
        struct bpf_program bpfprogram{};
        std::string program;
        switch (link_encap) {
            case DLT_PRISM_HEADER:
                std::cerr<<wlan<<" has DLT_PRISM_HEADER Encap\n";
                program = StringFormat::convert("radio[0x4a:4]==0x13223344 && radio[0x4e:2] == 0x55%.2x", radio_port);
                break;

            case DLT_IEEE802_11_RADIO:
                std::cerr<<wlan<<" has DLT_IEEE802_11_RADIO Encap\n";
                program = StringFormat::convert("ether[0x0a:4]==0x13223344 && ether[0x0e:2] == 0x55%.2x", radio_port);
                break;

            default:
                throw std::runtime_error(StringFormat::convert("unknown encapsulation on %s", wlan.c_str()));
        }
        if (pcap_compile(ppcap, &bpfprogram, program.c_str(), 1, 0) == -1) {
            throw std::runtime_error(StringFormat::convert("Unable to compile %s: %s", program.c_str(), pcap_geterr(ppcap)));
        }
        if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
            throw std::runtime_error(StringFormat::convert("Unable to set filter %s: %s", program.c_str(), pcap_geterr(ppcap)));
        }
        pcap_freecode(&bpfprogram);
        return ppcap;
    }
    static void writeAntennaStats(antenna_stat_t& antenna_stat,const uint8_t WLAN_IDX,const std::array<uint8_t,RX_ANT_MAX>& ant, const std::array<int8_t ,RX_ANT_MAX>& rssi){
        for (int i = 0; i < RX_ANT_MAX && ant[i] != 0xff; i++) {
            // key: addr + port + WLAN_IDX + ant
            uint64_t key = 0;
            key |= ((uint64_t) WLAN_IDX << 8 | (uint64_t) ant[i]);

            antenna_stat[key].addRSSI(rssi[i]);
        }
    }
    struct ParsedRxPcapPacket{
        std::array<uint8_t,RX_ANT_MAX> antenna;
        std::array<int8_t ,RX_ANT_MAX> rssi;
        const Ieee80211Header* ieee80211Header;
        const uint8_t* payload;
        const std::size_t payloadSize;
    };
    // Returns std::nullopt if this packet should not be processed further
    // else return the *parsed information*
    // To avoid confusion it might help to treat this method as a big black Box :)
    static std::optional<ParsedRxPcapPacket> processReceivedPcapPacket(const pcap_pkthdr& hdr, const uint8_t *pkt){
        int pktlen = hdr.caplen;
        int ant_idx = 0;
        std::array<uint8_t,RX_ANT_MAX> antenna{};
        // Fill all antenna slots with 0xff (unused)
        antenna.fill(0xff);
        std::array<int8_t ,RX_ANT_MAX> rssi{};
        // Fill all rssi slots with minimum value
        rssi.fill(SCHAR_MIN);
        uint8_t mIEEE80211_RADIOTAP_FLAGS = 0;
        uint8_t mIEEE80211_RADIOTAP_MCS=0;
        uint8_t mIEEE80211_RADIOTAP_CHANNEL=0;
        RadiotapHelper::debugRadiotapHeader(pkt, pktlen);
        struct ieee80211_radiotap_iterator iterator{};
        int ret = ieee80211_radiotap_iterator_init(&iterator, (ieee80211_radiotap_header *) pkt, pktlen, NULL);

        while (ret == 0 && ant_idx < RX_ANT_MAX) {
            ret = ieee80211_radiotap_iterator_next(&iterator);
            if (ret){
                continue;
            }
            /* see if this argument is something we can use */
            switch (iterator.this_arg_index) {
                 /*case IEEE80211_RADIOTAP_RATE:
                     // radiotap "rate" u8 is in
                     // 500kbps units, eg, 0x02=1Mbps
                 {
                     uint8_t pkt_rate = (*(uint8_t*)(iterator.this_arg))/2;
                     int rateInMbps=pkt_rate*2;
                     std::cout<<"Packet rate is "<<rateInMbps<<"\n";
                 }
                     break;*/
                case IEEE80211_RADIOTAP_ANTENNA:
                    // FIXME
                    // In case of multiple antenna stats in one packet this index will be irrelivant
                    antenna[ant_idx] = *(uint8_t *) (iterator.this_arg);
                    ant_idx += 1;
                    break;

                case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                    // Some cards can provide rssi for multiple antennas in one packet, so we should select maximum value
                    rssi[ant_idx] = *(int8_t *) (iterator.this_arg);
                    break;

                case IEEE80211_RADIOTAP_FLAGS:
                    mIEEE80211_RADIOTAP_FLAGS = *(uint8_t *) (iterator.this_arg);
                    break;
                case IEEE80211_RADIOTAP_MCS:
                    mIEEE80211_RADIOTAP_MCS = *(uint8_t *) (iterator.this_arg);
                case IEEE80211_RADIOTAP_CHANNEL:
                    mIEEE80211_RADIOTAP_CHANNEL=*(uint8_t *) (iterator.this_arg);
                default:
                    break;
            }
        }  /* while more rt headers */
        if (ret != -ENOENT && ant_idx < RX_ANT_MAX) {
            std::cerr<<"Error parsing radiotap header!\n";
            return std::nullopt;
        }
        if (mIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_BADFCS) {
            std::cerr<<"Got packet with bad fsc\n";
            return std::nullopt;
        }
        if (mIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_FCS) {
            //std::cout<<"Packet has IEEE80211_RADIOTAP_F_FCS";
            pktlen -= 4;
        }
#ifdef ENABLE_ADVANCED_DEBUGGING
        //std::cout<<RadiotapFlagsToString::flagsIEEE80211_RADIOTAP_MCS(mIEEE80211_RADIOTAP_MCS)<<"\n";
        //std::cout<<RadiotapFlagsToString::flagsIEEE80211_RADIOTAP_FLAGS(mIEEE80211_RADIOTAP_FLAGS)<<"\n";
        // With AR9271 I get 39 as length of the radio-tap header
        // With my internal laptop wifi chip I get 36 as length of the radio-tap header
        std::cout<<"iterator._max_length was "<<iterator._max_length<<"\n";
#endif
        /* discard the radiotap header part */
        pkt += iterator._max_length;
        pktlen -= iterator._max_length;
        //
        const Ieee80211Header* ieee80211Header=(Ieee80211Header*)pkt;
        const uint8_t* payload=pkt+Ieee80211Header::SIZE_BYTES;
        const std::size_t payloadSize=(std::size_t)pktlen-Ieee80211Header::SIZE_BYTES;
        return ParsedRxPcapPacket{antenna,rssi,ieee80211Header,payload,payloadSize};
    }
}

Aggregator::Aggregator(const std::string &client_addr, int client_udp_port,uint8_t radio_port, int k, int n, const std::string &keypair) :
FECDecoder(k,n),
CLIENT_UDP_PORT(client_udp_port),
RADIO_PORT(radio_port),
mDecryptor(keypair){
    sockfd = SocketHelper::open_udp_socket_for_tx(client_addr,client_udp_port);
    callback=std::bind(&Aggregator::sendPacketViaUDP, this, std::placeholders::_1,std::placeholders::_2);
}

Aggregator::~Aggregator() {
    close(sockfd);
}

void Aggregator::dump_stats(FILE *fp) {
    //timestamp in ms
    const uint64_t runTime=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-INIT_TIME).count();

    for (auto & it : antenna_stat) {
        fprintf(fp, "%" PRIu64 "\tANT\t%" PRIx64 "\t%d:%d:%d:%d\n", runTime, it.first, it.second.count_all,
                it.second.rssi_min, it.second.rssi_sum / it.second.count_all, it.second.rssi_max);
    }
    antenna_stat.clear();

    fprintf(fp, "%" PRIu64 "\tPKT\t%u:%u:%u:%u:%u:%u\n", runTime, count_p_all, count_p_dec_err, count_p_dec_ok,
            count_p_fec_recovered, count_p_lost, count_p_bad);
    fflush(fp);
    // the logger of svpcom prints what changed over time,
    // OpenHD wants absolute values
    statistics.count_p_all+=count_p_all;
    statistics.count_p_dec_err +=count_p_dec_err;
    statistics.count_p_dec_ok +=count_p_dec_ok;
    statistics.count_p_fec_recovered+=count_p_fec_recovered;
    statistics.count_p_lost+=statistics.count_p_lost;
    statistics.count_p_bad+=count_p_bad;
    openHdStatisticsWriter.writeStats(statistics);
    // it is actually much more understandable when I use the absolute values for the logging
    /*count_p_all = 0;
    count_p_dec_err = 0;
    count_p_dec_ok = 0;
    count_p_fec_recovered = 0;
    count_p_lost = 0;
    count_p_bad = 0;*/
#ifdef ENABLE_ADVANCED_DEBUGGING
    std::cout<<"avgPcapToApplicationLatency:"<<avgPcapToApplicationLatency.getAvgReadable()<<"\n";
    std::cout<<"avgLatencyBeaconPacketLatency"<<avgLatencyBeaconPacketLatency.getAvgReadable()<<"\n";
    //std::cout<<"avgLatencyBeaconPacketLatencyX:"<<avgLatencyBeaconPacketLatency.getNValuesLowHigh(20)<<"\n";
    std::cout<<"avgLatencyPacketInQueue"<<avgLatencyPacketInQueue.getAvgReadable()<<"\n";
#endif
}

void Aggregator::processPacket(const uint8_t WLAN_IDX,const pcap_pkthdr& hdr,const uint8_t* pkt){
#ifdef ENABLE_ADVANCED_DEBUGGING
    const auto tmp=GenericHelper::timevalToTimePointSystemClock(hdr.ts);
    const auto latency=std::chrono::system_clock::now() -tmp;
    avgPcapToApplicationLatency.add(latency);
#endif
    count_p_all++;
    // The radio capture header precedes the 802.11 header.
    const auto parsedPacket=RawTransmitterHelper::processReceivedPcapPacket(hdr, pkt);
    if(parsedPacket==std::nullopt){
        std::cerr<< "Discarding packet due to pcap parsing error (or wrong checksum)!\n";
        count_p_bad++;
        return;
    }
    // All these edge cases should NEVER happen if using a proper tx/rx setup and the wifi driver isn't complete crap
    if(parsedPacket->payloadSize<=0){
        std::cerr<<"Discarding packet due to no actual payload !\n";
        count_p_bad++;
        return;
    }
    if (parsedPacket->payloadSize > MAX_FORWARDER_PACKET_SIZE) {
        std::cerr<<"Discarding packet due to payload exceeding max "<<(int)parsedPacket->payloadSize<<"\n";
        count_p_bad++;
        return;
    }
    RawTransmitterHelper::writeAntennaStats(antenna_stat, WLAN_IDX, parsedPacket->antenna, parsedPacket->rssi);
    const Ieee80211Header* tmpHeader=parsedPacket->ieee80211Header;
    //std::cout<<"RADIO_PORT"<<(int)tmpHeader->getRadioPort()<<" IEEE_SEQ_NR "<<(int)tmpHeader->getSequenceNumber()<<"\n";
    //std::cout<<"FrameControl:"<<(int)tmpHeader->getFrameControl()<<"\n";
    //std::cout<<"DurationOrConnectionId:"<<(int)tmpHeader->getDurationOrConnectionId()<<"\n";

    // now to the actual payload
    const uint8_t *payload=parsedPacket->payload;
    const size_t payloadSize=parsedPacket->payloadSize;
    switch (payload[0]) {
        case WFB_PACKET_DATA:
            if (payloadSize < sizeof(WBDataHeader) + sizeof(FECDataHeader)) {
                std::cerr<<"short packet (fec header)\n";
                count_p_bad++;
                return;
            }
            break;
        case WFB_PACKET_KEY:
            if (payloadSize != WBSessionKeyPacket::SIZE_BYTES) {
                std::cerr<<"invalid session key packet\n";
                count_p_bad++;
                return;
            }
            if (mDecryptor.onNewPacketWfbKey(payload)) {
                count_p_dec_ok++;
                FECDecoder::reset();
            } else {
                count_p_dec_ok++;
            }
            return;
        case WFB_PACKET_LATENCY_BEACON:{
#ifdef ENABLE_ADVANCED_DEBUGGING
            // for testing only. It won't work if the tx and rx are running on different systems
            assert(payloadSize==sizeof(LatencyTestingPacket));
            const LatencyTestingPacket* latencyTestingPacket=(LatencyTestingPacket*)payload;
            const auto timestamp=std::chrono::time_point<std::chrono::steady_clock>(std::chrono::nanoseconds(latencyTestingPacket->timestampNs));
            const auto latency=std::chrono::steady_clock::now()-timestamp;
            //std::cout<<"Packet latency on this system is "<<std::chrono::duration_cast<std::chrono::nanoseconds>(latency).count()<<"\n";
            avgLatencyBeaconPacketLatency.add(latency);
#endif
        }
            return;
        default:
            std::cerr<<"Unknown packet type "<<(int)payload[0]<<" \n";
            count_p_bad += 1;
            return;
    }
    // FEC data or FEC correction packet
    WBDataPacket encryptedWbDataPacket=WBDataPacket::createFromRawMemory(payload, payloadSize);

    const auto decryptedPayload=mDecryptor.decryptPacket(encryptedWbDataPacket);
    if(decryptedPayload == std::nullopt){
        std::cerr << "unable to decrypt packet (block_idx,fragment_idx):" << encryptedWbDataPacket.wbDataHeader.getBlockIdx() << "," << (int)encryptedWbDataPacket.wbDataHeader.getFragmentIdx() << "\n";
        count_p_dec_err ++;
        return;
    }

    count_p_dec_ok++;

    assert(decryptedPayload->size() <= MAX_FEC_PAYLOAD);

    if(!FECDecoder::processPacket(encryptedWbDataPacket.wbDataHeader, *decryptedPayload)){
        count_p_bad++;
    }
}

//#define USE_PCAP_LOOP_INSTEAD_OF_NEXT

PcapReceiver::PcapReceiver(const std::string& wlan, int WLAN_IDX, int RADIO_PORT,Aggregator* agg) : WLAN_IDX(WLAN_IDX),RADIO_PORT(RADIO_PORT), agg(agg) {
    ppcap=RawTransmitterHelper::openRxWithPcap(wlan, RADIO_PORT);
#ifndef USE_PCAP_LOOP_INSTEAD_OF_NEXT
    fd = pcap_get_selectable_fd(ppcap);
#endif
}

PcapReceiver::~PcapReceiver() {
    close(fd);
    pcap_close(ppcap);
}

void PcapReceiver::loop_iter() {
    // loop while incoming queue is not empty
    int nPacketsPolledUntilQueueWasEmpty=0;
    for (;;){
        struct pcap_pkthdr hdr{};
        const uint8_t *pkt = pcap_next(ppcap, &hdr);
        if (pkt == nullptr) {
#ifdef ENABLE_ADVANCED_DEBUGGING
            std::cout<<"N of packets polled from pcap queue until empty: "<<nPacketsPolledUntilQueueWasEmpty<<"\n";
#endif
            break;
        }
        agg->processPacket(WLAN_IDX,hdr,pkt);
        nPacketsPolledUntilQueueWasEmpty++;
    }
}


#ifdef USE_PCAP_LOOP_INSTEAD_OF_NEXT
static void handler(u_char *user, const struct pcap_pkthdr *hdr,
                    const u_char * bytes){
    //const PcapReceiver* self2=(PcapReceiver*)self;
    //Aggregator* agg=(Aggregator*)user;
    PcapReceiver* self=(PcapReceiver*)user;
    //agg->processPacket(0,*hdr,bytes);
    self->agg->processPacket(self->WLAN_IDX,*hdr,bytes);
}

void PcapReceiver::xLoop() {
    pcap_loop(ppcap,0,handler, (u_char*) this);
}
#endif


void
radio_loop(std::shared_ptr<Aggregator> agg,const std::vector<std::string> rxInterfaces,const int radio_port,const std::chrono::milliseconds log_interval) {
    const int N_RECEIVERS = rxInterfaces.size();
    struct pollfd fds[N_RECEIVERS];
    PcapReceiver *rx[N_RECEIVERS];

    memset(fds, '\0', sizeof(fds));
    std::stringstream ss;
    ss<<"WB-RX Forwarding to: "<<agg->CLIENT_UDP_PORT<<" Assigned ID: "<<radio_port<<" Assigned WLAN(s):";

    for (int i = 0; i < N_RECEIVERS; i++) {
        rx[i] = new PcapReceiver(rxInterfaces[i], i, radio_port, agg.get());
        fds[i].fd = rx[i]->getfd();
        fds[i].events = POLLIN;
        ss<<rxInterfaces[i]<<" ";
    }
    std::cout<<ss.str()<<"\n";
#ifdef USE_PCAP_LOOP_INSTEAD_OF_NEXT
    rx[0]->xLoop();
#else
    std::chrono::steady_clock::time_point log_send_ts{};
    for (;;) {
        auto cur_ts=std::chrono::steady_clock::now();
        const int timeoutMS=log_send_ts > cur_ts ? (int)std::chrono::duration_cast<std::chrono::milliseconds>(log_send_ts - cur_ts).count() : 0;
        int rc = poll(fds, N_RECEIVERS,timeoutMS);

        if (rc < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            throw std::runtime_error(StringFormat::convert("Poll error: %s", strerror(errno)));
        }

        cur_ts = std::chrono::steady_clock::now();

        if (cur_ts >= log_send_ts) {
            agg->dump_stats(stdout);
            log_send_ts = std::chrono::steady_clock::now() + log_interval;
        }

        if (rc == 0) continue; // timeout expired

        for (int i = 0; rc > 0 && i < N_RECEIVERS; i++) {
            if (fds[i].revents & (POLLERR | POLLNVAL)) {
                throw std::runtime_error("socket error!");
            }
            if (fds[i].revents & POLLIN) {
                rx[i]->loop_iter();
                rc -= 1;
            }
        }
    }
#endif
}


int main(int argc, char *const *argv) {
    int opt;
    uint8_t k = 8, n = 12, radio_port = 1;
    std::chrono::milliseconds log_interval{1000};
    int client_udp_port = 5600;
    std::string client_addr = "127.0.0.1";
    std::string keypair = "gs.key";

    while ((opt = getopt(argc, argv, "K:k:n:c:u:p:l:")) != -1) {
        switch (opt) {
            case 'K':
                keypair = optarg;
                break;
            case 'k':
                k = atoi(optarg);
                break;
            case 'n':
                n = atoi(optarg);
                break;
            case 'c':
                client_addr = std::string(optarg);
                break;
            case 'u':
                client_udp_port = atoi(optarg);
                break;
            case 'p':
                radio_port = atoi(optarg);
                break;
            case 'l':
                log_interval = std::chrono::milliseconds(atoi(optarg));
                break;
            default: /* '?' */
            show_usage:
                fprintf(stderr,
                        "Local receiver: %s [-K rx_key] [-k RS_K] [-n RS_N] [-c client_addr] [-u client_port] [-p radio_port] [-l log_interval] interface1 [interface2] ...\n",
                        argv[0]);
                fprintf(stderr, "Default: K='%s', k=%d, n=%d, connect=%s:%d, radio_port=%d, log_interval=%d\n",
                        keypair.c_str(), k, n, client_addr.c_str(), client_udp_port, radio_port, (int)std::chrono::duration_cast<std::chrono::milliseconds>(log_interval).count());
                fprintf(stderr, "WFB version "
                WFB_VERSION
                "\n");
                exit(1);
        }
    }
    const int nRxInterfaces=argc-optind;
    if(nRxInterfaces>MAX_RX_INTERFACES){
        std::cout<<"Too many RX interfaces "<<nRxInterfaces<<"\n";
        goto show_usage;
    }
    std::vector<std::string> rxInterfaces;
    for (int i = 0; i < nRxInterfaces; i++) {
        rxInterfaces.push_back(argv[optind + i]);
    }
    try {
        std::shared_ptr<Aggregator> agg=std::make_shared<Aggregator>(client_addr, client_udp_port,radio_port, k, n, keypair);
        radio_loop(agg,rxInterfaces, radio_port, log_interval);
    } catch (std::runtime_error &e) {
        fprintf(stderr, "Error: %s\n", e.what());
        exit(1);
    }
    return 0;
}
