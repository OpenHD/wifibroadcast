#ifndef WIFIBROADCAST_WBDATASTREAMTXUDP_H
#define WIFIBROADCAST_WBDATASTREAMTXUDP_H

#include "HelperSources/SocketHelper.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "WBStreamTx.h"

/**
 * Uses UDP for data in instead of callback, specifically for
 * WB_PACKET_TYPE_DATA.
 */
class WBDataStreamTxUDP {
 public:
  WBDataStreamTxUDP(std::shared_ptr<WBTxRx> txrx, WBStreamTx::Options options,
                    int fec_k, int in_udp_port) {
    options.default_packet_type = WB_PACKET_TYPE_DATA;
    radiotap_header_holder = std::make_shared<RadiotapHeaderTxHolder>();
    wb_tx = std::make_unique<WBStreamTx>(txrx, options, radiotap_header_holder);
    last_udp_in_packet_ts_ms = MyTimeHelper::get_curr_time_ms();

    auto cb_udp_in = [this, options, fec_k](
                         const uint8_t *payload,
                         const std::size_t payloadSize) mutable {
      last_udp_in_packet_ts_ms = MyTimeHelper::get_curr_time_ms();
      if (options.enable_fec) {
        auto packet = std::make_shared<std::vector<uint8_t>>(
            payload, payload + payloadSize);
        m_block.push_back(packet);
        if (m_block.size() == fec_k) {
          wb_tx->try_enqueue_block_with_type(m_block, 100, 20,
                                             WB_PACKET_TYPE_DATA);
          m_block.clear();
        }
      } else {
        auto packet = std::make_shared<std::vector<uint8_t>>(
            payload, payload + payloadSize);
        wb_tx->try_enqueue_packet(packet);
      }
    };
    m_udp_in = std::make_unique<SocketHelper::UDPReceiver>(
        SocketHelper::ADDRESS_LOCALHOST, in_udp_port, cb_udp_in);
    m_udp_in->runInBackground();
    auto console = wifibroadcast::log::create_or_get(
        fmt::format("udp{}->radio_port{}", in_udp_port, options.radio_port));
    console->info("Expecting data on localhost:{}", in_udp_port);
    if (options.enable_fec) {
      console->warn("This buffers {} packets on udp in !", fec_k);
    }
  }
  std::unique_ptr<WBStreamTx> wb_tx;
  std::shared_ptr<RadiotapHeaderTxHolder> radiotap_header_holder;
  std::unique_ptr<SocketHelper::UDPReceiver> m_udp_in;
  int last_udp_in_packet_ts_ms;

 private:
  std::vector<std::shared_ptr<std::vector<uint8_t>>> m_block;
};

#endif  // WIFIBROADCAST_WBDATASTREAMTXUDP_H
