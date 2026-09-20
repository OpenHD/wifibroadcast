#include <unistd.h>
#include <thread>
#include <chrono>

#include "../src/HelperSources/SocketHelper.hpp"
#include "../src/HelperSources/TimeHelper.hpp"
#include "../src/WBDataStreamRxUDP.h"
#include "../src/WBDataStreamTxUDP.h"
#include "../src/WBTxRx.h"
#include "../src/wifibroadcast_spdlog.h"

int main(int argc, char *const *argv) {
  std::string card = "wlxac9e17596103";
  bool is_air = false;
  bool enable_fec = true;
  int opt;
  while ((opt = getopt(argc, argv, "w:agf")) != -1) {
    switch (opt) {
      case 'w': card = optarg; break;
      case 'a': is_air = true; break;
      case 'g': is_air = false; break;
      case 'f': enable_fec = true; break;
      default: exit(1);
    }
  }

  auto console = wifibroadcast::log::create_or_get("main");
  console->info("Running as {} on card {}", (is_air ? "Air" : "Ground"), card);

  std::vector<wifibroadcast::WifiCard> cards;
  wifibroadcast::WifiCard tmp_card{card, 1};
  cards.push_back(tmp_card);
  WBTxRx::Options options_txrx{};
  auto radiotap_header_holder = std::make_shared<RadiotapHeaderTxHolder>();
  std::shared_ptr<WBTxRx> txrx =
      std::make_shared<WBTxRx>(cards, options_txrx, radiotap_header_holder);

  if (is_air) {
    WBStreamTx::Options options_tx{};
    options_tx.radio_port = 11;
    options_tx.enable_fec = enable_fec;
    const auto FEC_K = 8;
    auto data_tx = std::make_unique<WBDataStreamTxUDP>(txrx, options_tx, FEC_K, 5700);

    txrx->start_receiving();
    while (true) { std::this_thread::sleep_for(std::chrono::seconds(1)); }
  } else {
    WBStreamRx::Options options_rx{};
    options_rx.radio_port = 11;
    options_rx.enable_fec = enable_fec;
    auto data_rx = std::make_unique<WBDataStreamRxUDP>(txrx, options_rx, 5701);

    txrx->start_receiving();
    while (true) { std::this_thread::sleep_for(std::chrono::seconds(1)); }
  }
}
