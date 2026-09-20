#ifndef WIFIBROADCAST_WBDATASTREAMTXUDP_H
#define WIFIBROADCAST_WBDATASTREAMTXUDP_H

#include "HelperSources/SocketHelper.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "WBStreamTx.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>

/**
 * Uses UDP for data in instead of callback, specifically for
 * WB_PACKET_TYPE_DATA.
 */
class WBDataStreamTxUDP {
 public:
  WBDataStreamTxUDP(std::shared_ptr<WBTxRx> txrx, WBStreamTx::Options options,
                    int fec_k, int in_udp_port, int fec_overhead_percent = 20,
                    int max_payload_bitrate_kbits = 0) {
    options.default_packet_type = WB_PACKET_TYPE_DATA;
    radiotap_header_holder = std::make_shared<RadiotapHeaderTxHolder>();
    wb_tx = std::make_unique<WBStreamTx>(txrx, options, radiotap_header_holder);
    last_udp_in_packet_ts_ms = MyTimeHelper::get_curr_time_ms();

    m_fec_overhead_percent = fec_overhead_percent;
    m_max_payload_bitrate_kbits = max_payload_bitrate_kbits;
    auto cb_udp_in = [this, options, fec_k](
                         const uint8_t *payload,
                         const std::size_t payloadSize) mutable {
      last_udp_in_packet_ts_ms = MyTimeHelper::get_curr_time_ms();
      if (!consume_budget(payloadSize)) {
        ++m_dropped_rate_limited_packets;
        return;
      }
      m_accepted_bytes += payloadSize;
      if (options.enable_fec) {
        auto packet = std::make_shared<std::vector<uint8_t>>(
            payload, payload + payloadSize);
        m_block.push_back(packet);
        if (m_block.size() == fec_k) {
          wb_tx->try_enqueue_block_with_type(m_block, 100,
                                             m_fec_overhead_percent.load(),
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
  void set_max_payload_bitrate_kbits(int value) {
    m_max_payload_bitrate_kbits = value;
  }
  uint64_t accepted_bytes() const { return m_accepted_bytes.load(); }
  uint64_t dropped_rate_limited_packets() const {
    return m_dropped_rate_limited_packets.load();
  }

 private:
  bool consume_budget(std::size_t payload_size) {
    const int cap_kbits = m_max_payload_bitrate_kbits.load();
    if (cap_kbits <= 0) return true;
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(m_budget_mutex);
    const double elapsed =
        std::chrono::duration<double>(now - m_budget_updated).count();
    const double bytes_per_second = cap_kbits * 1000.0 / 8.0;
    m_budget_bytes = std::min(bytes_per_second,
                              m_budget_bytes + elapsed * bytes_per_second);
    m_budget_updated = now;
    if (m_budget_bytes < payload_size) return false;
    m_budget_bytes -= payload_size;
    return true;
  }
  std::vector<std::shared_ptr<std::vector<uint8_t>>> m_block;
  std::atomic<int> m_fec_overhead_percent{20};
  std::atomic<int> m_max_payload_bitrate_kbits{0};
  std::atomic<uint64_t> m_accepted_bytes{0};
  std::atomic<uint64_t> m_dropped_rate_limited_packets{0};
  std::mutex m_budget_mutex;
  std::chrono::steady_clock::time_point m_budget_updated =
      std::chrono::steady_clock::now();
  double m_budget_bytes = 0.0;
};

#endif  // WIFIBROADCAST_WBDATASTREAMTXUDP_H
