#ifndef WIFIBROADCAST_WBDATASTREAMRXUDP_H
#define WIFIBROADCAST_WBDATASTREAMRXUDP_H

#include "WBStreamRx.h"
#include "HelperSources/SocketHelper.hpp"

/**
 * Uses UDP for data out instead of callback, specifically for WB_PACKET_TYPE_DATA.
 */
class WBDataStreamRxUDP {
 public:
  WBDataStreamRxUDP(std::shared_ptr<WBTxRx> txrx, WBStreamRx::Options options,
                    int udp_port_out) {
    m_udp_out = std::make_unique<SocketHelper::UDPForwarder>(
        SocketHelper::ADDRESS_LOCALHOST, udp_port_out);
    wb_rx = std::make_unique<WBStreamRx>(txrx, options);
    auto cb = [this](const uint8_t *payload, const std::size_t payloadSize) {
      m_udp_out->forwardPacketViaUDP(payload, payloadSize);
    };
    wb_rx->set_callback(cb);
    auto console = wifibroadcast::log::create_or_get(
        fmt::format("radio_port{}->udp{}", options.radio_port, udp_port_out));
    console->info("Sending data to localhost:{}", udp_port_out);
  }
  std::unique_ptr<SocketHelper::UDPForwarder> m_udp_out;
  std::unique_ptr<WBStreamRx> wb_rx;

 private:
};

#endif  // WIFIBROADCAST_WBDATASTREAMRXUDP_H
