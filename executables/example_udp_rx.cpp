//
// Created by consti10 on 01.07.23.
//

#include "../src/WBStreamRx.h"
#include "../src/WBStreamTx.h"
#include "../src/ExtTxRx.h"
#include "../src/wifibroadcast_spdlog.h"

/**
 * Simple demo application that sends out hello messages and listens for hello messages.
 * You can run it either on 2 different systems (air unit and ground unit)
 * or run it on the same system with 2 different wifi cards for testing.
 *
 * On success, you should see the air unit talking to the ground unit and vice versa.
 *
 * NOTE: Card(s) need to be in monitor mode & on match on the selected frequency !
 * NOTE: This example is as simple as possible, and therefore doesn't even need to use the WBStreamTX / WBStreamRX pair
 */
int main(int argc, char *const *argv) {
  bool advanced_debugging= false;
  bool is_air= false;
  bool air_or_ground_explicitly_specified= false;
  int opt;

  if(!air_or_ground_explicitly_specified){
    std::cerr<<"Warning - please specify air or ground, air only talks to ground and vice versa"<<std::endl;
  }
  //std::cout<<"Running as "<<(is_air ? "Air" : "Ground")<<" on card "<<card<<"\n";

  // Create the Tx-RX
  std::vector<ExtTxRx::UdpWifiCard> cards;
  ExtTxRx::UdpWifiCard tmp_card{4321};
  cards.push_back(tmp_card);
  ExtTxRx::Options options_txrx{};
  options_txrx.pcap_rx_set_direction = true;
  options_txrx.use_gnd_identifier=!is_air;
  if(advanced_debugging){
    options_txrx.log_all_received_validated_packets= true;
    options_txrx.advanced_debugging_rx= true;
  }

  std::shared_ptr<ExtTxRx> txrx = std::make_shared<ExtTxRx>(cards, options_txrx);

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
    txrx->tx_inject_packet(0,(uint8_t*)message.data(),message.size());

    std::this_thread::sleep_for(std::chrono::milliseconds (1000));
    const auto elapsed_since_last_log=std::chrono::steady_clock::now()-lastLog;
    if(elapsed_since_last_log>std::chrono::seconds(4)){
      lastLog=std::chrono::steady_clock::now();
      auto txStats=txrx->get_tx_stats();
      auto rxStats=txrx->get_rx_stats();
      auto rx_stats_card0=txrx->get_rx_stats_for_card(0);
      std::cout<<txStats<<std::endl;
      std::cout<<rx_stats_card0<<std::endl;
    }
  }
}