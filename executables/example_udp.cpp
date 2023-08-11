//
// Created by consti10 on 30.06.23.
//

#include "../src/WBStreamRx.h"
#include "../src/WBStreamTx.h"
#include "../src/WBTxRx.h"
#include "../src/wifibroadcast-spdlog.h"
#include "../src/HelperSources/SocketHelper.hpp"
#include "RandomBufferPot.hpp"
#include "../src/HelperSources/TimeHelper.hpp"
#include "../src/legacy/WBStreamRxUDP.h"
#include "../src/legacy/WBStreamTxUDP.h"

/**
 * Simple example application that uses UDP as data input / output
 * Feed in udp packets on air to port 5600 -> get out udp packets on ground on port 5601
 * I use different in / out udp ports here in case you wanna use the application locally
 * ( 2 cards talking, but on the same system)
 *
 * NOTE: The input stream can be protected by FEC - but this serves only demo purposes here
 * For proper usage of FEC during wifibroadcast video streaming (no latency overhead), please check out openhd.
 * ! IN THIS EXAMPLE, IF FEC IS ENABLED, 8 UDP PACKETS ARE BUFFERED BEFORE FORWARDING !
 *
 * NOTE: This example does not support running another instance of it simultaneously - if you want to do multiplexing,
 * do it in c++ code, you cannot do it via shell anymore ! This might be harder to start with, but gives a lot of advantages,
 * like easier debugging (only debug one single application, not 100s of open terminals), and tighter control over packet queues / less latency
 * due to no UDP.
 *
 * When run as air: Expects UDP data on port 5600
 * When run as ground: Forwards UDP data to port 5601
 */
int main(int argc, char *const *argv) {
  std::string card="wlxac9e17596103";
  bool pcap_setdirection= true;
  bool is_air= false;
  bool air_or_ground_explicitly_specified= false;
  bool enable_fec= false;
  int opt;
  while ((opt = getopt(argc, argv, "w:agdf")) != -1) {
    switch (opt) {
      case 'w':
        card = optarg;
        break;
      case 'a':
        is_air= true;
        air_or_ground_explicitly_specified= true;
        break ;
      case 'g':
        is_air= false;
        air_or_ground_explicitly_specified= true;
        break ;
      case 'f':
        enable_fec= true;
        break ;
      case 'd':
        pcap_setdirection= false;
        break ;
      default: /* '?' */
      show_usage:
        fprintf(stderr,
                "Example hello %s [-a run as air] [-g run as ground] [-f enable fec (default off),NEEDS TO MATCH on air / ground ] [-w wifi card to use] ...\n",
                argv[0]);
        exit(1);
    }
  }
  if(!air_or_ground_explicitly_specified){
    std::cerr<<"Warning - please specify air or ground, air only talks to ground and vice versa"<<std::endl;
  }
  auto console=wifibroadcast::log::create_or_get("main");
  console->info("Running as {} on card {}",(is_air ? "Air" : "Ground"),card);

  std::vector<WBTxRx::WifiCard> cards;
  WBTxRx::WifiCard tmp_card{card,1};
  cards.push_back(tmp_card);
  WBTxRx::Options options_txrx{};
  //options_txrx.pcap_rx_set_direction= false;
  options_txrx.pcap_rx_set_direction = pcap_setdirection;
  options_txrx.log_all_received_validated_packets= false;

  std::shared_ptr<WBTxRx> txrx=std::make_shared<WBTxRx>(cards,options_txrx);

  if(is_air){
    // UDP in and inject packets
    WBStreamTx::Options options_tx{};
    options_tx.radio_port=10;
    options_tx.enable_fec= enable_fec;
    const auto FEC_K=8; // arbitrary chosen
    auto wb_stream_udp_tx=std::make_unique<WBStreamTxUDP>(txrx,options_tx,FEC_K,5600);
    //
    // For proper application -create more TX / RX stream(s) here if you need
    //
    txrx->start_receiving();
    auto lastLog=std::chrono::steady_clock::now();
    while (true){
      std::this_thread::sleep_for(std::chrono::milliseconds (500));
      const auto elapsed_since_last_log=std::chrono::steady_clock::now()-lastLog;
      if(elapsed_since_last_log>std::chrono::seconds(1)){
        lastLog=std::chrono::steady_clock::now();
        auto txStats=txrx->get_tx_stats();
        std::cout<<txStats<<std::endl;
      }
      auto elapsed_since_last_udp_packet=MyTimeHelper::get_curr_time_ms()-wb_stream_udp_tx->last_udp_in_packet_ts_ms;
      const int UDP_LAST_PACKET_MIN_INTERVAL_S=2;
      if(elapsed_since_last_udp_packet>1000*UDP_LAST_PACKET_MIN_INTERVAL_S){
        console->warn("No udp packet in for >= {} seconds",UDP_LAST_PACKET_MIN_INTERVAL_S);
      }
    }
  }else{
    // listen for packets and udp out
    WBStreamRx::Options options_rx{};
    options_rx.radio_port=10;
    options_rx.enable_fec= enable_fec;
    auto wb_stream_udp_rx=std::make_unique<WBStreamRxUDP>(txrx,options_rx,5601);
    //
    // For proper application -create more TX / RX stream(s) here if you need
    //
    txrx->start_receiving();
    auto lastLog=std::chrono::steady_clock::now();
    while (true){
      std::this_thread::sleep_for(std::chrono::milliseconds (500));
      const auto elapsed_since_last_log=std::chrono::steady_clock::now()-lastLog;
      if(elapsed_since_last_log>std::chrono::seconds(1)){
        lastLog=std::chrono::steady_clock::now();
        auto txStats=txrx->get_tx_stats();
        auto rxStats=txrx->get_rx_stats();
        auto rx_stats_card0=txrx->get_rx_stats_for_card(0);
        std::cout<<txStats<<std::endl;
        std::cout<<rx_stats_card0<<std::endl;
      }
    }
  }
}