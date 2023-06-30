//
// Created by consti10 on 27.06.23.
//

#include "../src/WBStreamRx.h"
#include "../src/WBStreamTx.h"
#include "../src/WBTxRx.h"
#include "../src/wifibroadcast-spdlog.h"
#include "RandomBufferPot.hpp"

int main(int argc, char *const *argv) {
  std::string card="wlxac9e17596103";
  bool pcap_setdirection= true;
  int opt;
  while ((opt = getopt(argc, argv, "w:d")) != -1) {
    switch (opt) {
      case 'w':
        card = optarg;
        break;
      case 'd':
        pcap_setdirection= false;
        break ;
      default: /* '?' */
      show_usage:
        fprintf(stderr,
                "Local receiver: %s [-K rx_key] [-c client_addr] [-u udp_client_port] [-r radio_port] interface1 [interface2] ...\n",
                argv[0]);
        exit(1);
    }
  }

  std::vector<std::string> cards{card};
  WBTxRx::Options options_txrx{};
  options_txrx.rtl8812au_rssi_fixup= true;
  //options_txrx.set_direction= false;
  options_txrx.set_direction= pcap_setdirection;
  options_txrx.log_all_received_validated_packets= true;

  std::shared_ptr<WBTxRx> txrx=std::make_shared<WBTxRx>(cards,options_txrx);

  const bool enable_fec= true;
  WBStreamTx::Options options_tx{};
  options_tx.radio_port=10;
  options_tx.enable_fec= enable_fec;
  std::unique_ptr<WBStreamTx> wb_tx=std::make_unique<WBStreamTx>(txrx,options_tx);

  WBStreamRx::Options options_rx{};
  options_rx.radio_port=10;
  options_rx.enable_fec= enable_fec;
  std::unique_ptr<WBStreamRx> wb_rx=std::make_unique<WBStreamRx>(txrx,options_rx);
  auto console=wifibroadcast::log::create_or_get("out_cb");
  auto cb=[&console](const uint8_t *payload, const std::size_t payloadSize){
      console->debug("Got data {}",payloadSize);
  };
  wb_rx->set_callback(cb);

  txrx->start_receiving();

  const auto randomBufferPot = std::make_unique<RandomBufferPot>(1000, 1024);

  while (true){
    for(int i=0;i<100;i++){
      auto dummy_packet=randomBufferPot->getBuffer(i);
      //txrx->tx_inject_packet(0,dummy_packet->data(),dummy_packet->size());
      if(enable_fec){
        wb_tx->try_enqueue_block({dummy_packet},10,10);
      }else{
        wb_tx->try_enqueue_packet(dummy_packet);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds (500));
    }
  }
}