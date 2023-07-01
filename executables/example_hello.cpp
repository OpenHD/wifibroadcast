//
// Created by consti10 on 01.07.23.
//

#include "../src/WBStreamRx.h"
#include "../src/WBStreamTx.h"
#include "../src/WBTxRx.h"
#include "../src/wifibroadcast-spdlog.h"
#include "RandomBufferPot.hpp"

/**
 * Simple demo application that sends out hello messages and listens for hello messages.
 * You can run it either on 2 different systems (air unit and ground unit)
 * or run it on the same system with 2 different wifi cards for testing.
 *
 * On success, you should see the air unit talking to the ground unit and vice versa.
 *
 * NOTE: Card(s) need to be in monitor mode & on match on the selected frequency !
 */
int main(int argc, char *const *argv) {
  std::string card="wlxac9e17596103";
  bool pcap_setdirection= true;
  bool is_air= false;
  int opt;
  while ((opt = getopt(argc, argv, "w:agd")) != -1) {
    switch (opt) {
      case 'w':
        card = optarg;
        break;
      case 'a':
        is_air= true;
        break ;
      case 'g':
        is_air= false;
        break ;
      case 'd':
        pcap_setdirection= false;
        break ;
      default: /* '?' */
      show_usage:
        fprintf(stderr,
                "Example hello %s [-a run as air] [-g run as ground] [-w wifi card to use] ...\n",
                argv[0]);
        exit(1);
    }
  }
  std::cout<<"Running as "<<(is_air ? "Air" : "Ground")<<" on card "<<card<<"\n";

  // Create the Tx-RX
  std::vector<std::string> cards{card};
  WBTxRx::Options options_txrx{};
  options_txrx.rtl8812au_rssi_fixup= true;
  //options_txrx.set_direction= false;
  options_txrx.set_direction= pcap_setdirection;
  options_txrx.log_all_received_validated_packets= true;

  std::shared_ptr<WBTxRx> txrx=std::make_shared<WBTxRx>(cards,options_txrx);

  txrx->start_receiving();

  WBTxRx::OUTPUT_DATA_CALLBACK cb=[](uint64_t nonce,int wlan_index,const uint8_t radioPort,const uint8_t *data, const std::size_t data_len){
    std::string message((const char*)data,data_len);
    fmt::print("Got packet[{}]\n",message);
  };
  txrx->rx_register_callback(cb);

  auto lastLog=std::chrono::steady_clock::now();
  int packet_index=0;
  while (true){
    auto message=is_air ? fmt::format("Air says hello {}",packet_index) : fmt::format("Ground says hello {}",packet_index);
    packet_index++;

    // Just use radio port 0 - we don't need multiplexing in this example
    // This message is injected on the wifi card
    txrx->tx_inject_packet(0,(uint8_t*)message.data(),message.size()+1);

    std::this_thread::sleep_for(std::chrono::milliseconds (1000));
    const auto elapsed_since_last_log=std::chrono::steady_clock::now()-lastLog;
    if(elapsed_since_last_log>std::chrono::seconds(4)){
      lastLog=std::chrono::steady_clock::now();
      auto txStats=txrx->get_tx_stats();
      auto rxStats=txrx->get_rx_stats();
      auto rssi=txrx->get_rx_stats_for_card(0);
      std::cout<<txStats<<std::endl;
      std::cout<<rxStats<<" RSSI:"<<(int)rssi.rssi_for_wifi_card.last_rssi<<std::endl;
    }
  }
}