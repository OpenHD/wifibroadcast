
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
#include "rx.hpp"
#include "wifibroadcast.hpp"
#include <cassert>
#include <cstdio>
#include <cinttypes>
#include <unistd.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <memory>
#include <string>
#include <chrono>
#include <sstream>

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
        // Important: Without enabling this mode pcap buffers quite a lot of packets starting with version 1.5.0 !
        // https://www.tcpdump.org/manpages/pcap_set_immediate_mode.3pcap.html
        if(pcap_set_immediate_mode(ppcap,true)!=0)throw std::runtime_error(StringFormat::convert("pcap_set_immediate_mode failed: %s", pcap_geterr(ppcap)));
        if (pcap_activate(ppcap) != 0) throw std::runtime_error(StringFormat::convert("pcap_activate failed: %s", pcap_geterr(ppcap)));
        if (pcap_setnonblock(ppcap, 1, errbuf) != 0) throw std::runtime_error(StringFormat::convert("set_nonblock failed: %s", errbuf));

        int link_encap = pcap_datalink(ppcap);
        struct bpf_program bpfprogram{};
        std::string program;
        switch (link_encap) {
            case DLT_PRISM_HEADER:
                std::cout<<wlan<<" has DLT_PRISM_HEADER Encap\n";
                program = StringFormat::convert("radio[0x4a:4]==0x13223344 && radio[0x4e:2] == 0x55%.2x", radio_port);
                break;

            case DLT_IEEE802_11_RADIO:
                std::cout<<wlan<<" has DLT_IEEE802_11_RADIO Encap\n";
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

    struct ParsedRxPcapPacket{
        // Size can be anything from size=1 to size== N where N is the number of Antennas of this adapter
        const std::vector<RssiForAntenna> allAntennaValues;
        const Ieee80211Header* ieee80211Header;
        const uint8_t* payload;
        const std::size_t payloadSize;
    };
    // Returns std::nullopt if this packet should not be processed further
    // else return the *parsed information*
    // To avoid confusion it might help to treat this method as a big black Box :)
    static std::optional<ParsedRxPcapPacket> processReceivedPcapPacket(const pcap_pkthdr& hdr, const uint8_t *pkt){
        int pktlen = hdr.caplen;
        // Copy the value of this flag once present and process it after the loop is done
        uint8_t tmpCopyOfIEEE80211_RADIOTAP_FLAGS = 0;
        //RadiotapHelper::debugRadiotapHeader(pkt, pktlen);
        struct ieee80211_radiotap_iterator iterator{};
        // With AR9271 I get 39 as length of the radio-tap header
        // With my internal laptop wifi chip I get 36 as length of the radio-tap header.
        int ret = ieee80211_radiotap_iterator_init(&iterator, (ieee80211_radiotap_header *) pkt, pktlen, NULL);
        uint8_t currentAntenna=0;
        // not confirmed yet, but one pcap packet might include stats for multiple antennas
        std::vector<RssiForAntenna> allAntennaValues;
        while (ret == 0 ) {
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
                    // RADIOTAP_DBM_ANTSIGNAL should come directly afterwards
                    currentAntenna=iterator.this_arg[0];
                    break;
                case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                    allAntennaValues.push_back({currentAntenna,*((int8_t*)iterator.this_arg)});
                    break;
                case IEEE80211_RADIOTAP_FLAGS:
                    tmpCopyOfIEEE80211_RADIOTAP_FLAGS = *(uint8_t *) (iterator.this_arg);
                    break;
                default:
                    break;
            }
        }  /* while more rt headers */
        if (ret != -ENOENT) {
            std::cerr<<"Error parsing radiotap header!\n";
            return std::nullopt;
        }
        if (tmpCopyOfIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_BADFCS) {
            std::cerr<<"Got packet with bad fsc\n";
            return std::nullopt;
        }
        if (tmpCopyOfIEEE80211_RADIOTAP_FLAGS & IEEE80211_RADIOTAP_F_FCS) {
            //std::cout<<"Packet has IEEE80211_RADIOTAP_F_FCS";
            pktlen -= 4;
        }
#ifdef ENABLE_ADVANCED_DEBUGGING
        //std::cout<<RadiotapFlagsToString::flagsIEEE80211_RADIOTAP_MCS(mIEEE80211_RADIOTAP_MCS)<<"\n";
        //std::cout<<RadiotapFlagsToString::flagsIEEE80211_RADIOTAP_FLAGS(mIEEE80211_RADIOTAP_FLAGS)<<"\n";
        // With AR9271 I get 39 as length of the radio-tap header
        // With my internal laptop wifi chip I get 36 as length of the radio-tap header
        //std::cout<<"iterator._max_length was "<<iterator._max_length<<"\n";
#endif
        //assert(iterator._max_length==hdr.caplen);
        /* discard the radiotap header part */
        pkt += iterator._max_length;
        pktlen -= iterator._max_length;
        //
        const Ieee80211Header* ieee80211Header=(Ieee80211Header*)pkt;
        const uint8_t* payload=pkt+Ieee80211Header::SIZE_BYTES;
        const std::size_t payloadSize=(std::size_t)pktlen-Ieee80211Header::SIZE_BYTES;
        return ParsedRxPcapPacket{allAntennaValues,ieee80211Header,payload,payloadSize};
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
    // first forward to OpenHD
    openHdStatisticsWriter.writeStats({
        count_p_all,count_p_dec_err,count_p_dec_ok,count_p_fec_recovered,count_p_lost,count_p_bad,rssiForWifiCard
    });
    //timestamp in ms
    const uint64_t runTime=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-INIT_TIME).count();
    for(auto& wifiCard : rssiForWifiCard){
        // no new rssi values for this card since the last call
        if(wifiCard.count_all==0)continue;
        std::cout<<"RSSI Count|Min|Max|Avg: "<<(int)wifiCard.count_all<<":"<<(int)wifiCard.rssi_min<<":"<<(int)wifiCard.rssi_max<<":"<<(int)wifiCard.getAverage()<<"\n";
        wifiCard.reset();
    }
    fprintf(fp, "%" PRIu64 "\tPKT\t%u:%u:%u:%u:%u:%u\n", runTime, count_p_all, count_p_dec_err, count_p_dec_ok,
            count_p_fec_recovered, count_p_lost, count_p_bad);
    fflush(fp);
    // it is actually much more understandable when I use the absolute values for the logging
    /*count_p_all = 0;
    count_p_dec_err = 0;
    count_p_dec_ok = 0;
    count_p_fec_recovered = 0;
    count_p_lost = 0;
    count_p_bad = 0;*/
#ifdef ENABLE_ADVANCED_DEBUGGING
    std::cout<<"avgPcapToApplicationLatency: "<<avgPcapToApplicationLatency.getAvgReadable()<<"\n";
    std::cout<<"nOfPacketsPolledFromPcapQueuePerIteration: "<<nOfPacketsPolledFromPcapQueuePerIteration.getAvgReadable()<<"\n";
    nOfPacketsPolledFromPcapQueuePerIteration.reset();
    //std::cout<<"avgLatencyBeaconPacketLatency"<<avgLatencyBeaconPacketLatency.getAvgReadable()<<"\n";
    //std::cout<<"avgLatencyBeaconPacketLatencyX:"<<avgLatencyBeaconPacketLatency.getNValuesLowHigh(20)<<"\n";
    //std::cout<<"avgLatencyPacketInQueue"<<avgLatencyPacketInQueue.getAvgReadable()<<"\n";
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
    if(parsedPacket->ieee80211Header->getRadioPort()!=RADIO_PORT) {
        // If we have the proper filter on pcap only packets with the right radiotap port should pass through
        std::cerr<<"Got packet with wrong radio port "<<(int)parsedPacket->ieee80211Header->getRadioPort()<<"\n";
        //RadiotapHelper::debugRadiotapHeader(pkt,hdr.caplen);
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
    if(parsedPacket->allAntennaValues.size()>MAX_N_ANTENNAS_PER_WIFI_CARD){
        std::cerr<<"Wifi card with "<<parsedPacket->allAntennaValues.size()<<" antennas\n";
    }
    auto& thisWifiCard=rssiForWifiCard[WLAN_IDX];
    for(const auto& value : parsedPacket->allAntennaValues){
        // don't care from which antenna the value came
        thisWifiCard.addRSSI(value.rssi);
    }

    //RawTransmitterHelper::writeAntennaStats(antenna_stat, WLAN_IDX, parsedPacket->antenna, parsedPacket->rssi);
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

PcapReceiver::PcapReceiver(const std::string& wlan, int WLAN_IDX, int RADIO_PORT,Aggregator* agg) : WLAN_IDX(WLAN_IDX),RADIO_PORT(RADIO_PORT), agg(agg) {
    ppcap=RawTransmitterHelper::openRxWithPcap(wlan, RADIO_PORT);
    fd = pcap_get_selectable_fd(ppcap);
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
            //std::cout<<"N of packets polled from pcap queue until empty: "<<nPacketsPolledUntilQueueWasEmpty<<"\n";
            agg->nOfPacketsPolledFromPcapQueuePerIteration.add(nPacketsPolledUntilQueueWasEmpty);
#endif
            break;
        }
        timeForParsingPackets.start();
        agg->processPacket(WLAN_IDX,hdr,pkt);
        timeForParsingPackets.stop();
#ifdef ENABLE_ADVANCED_DEBUGGING
        // how long the cpu spends on agg.processPacket
        timeForParsingPackets.printInIntervalls(std::chrono::seconds(1));
#endif
        nPacketsPolledUntilQueueWasEmpty++;
    }
}


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
