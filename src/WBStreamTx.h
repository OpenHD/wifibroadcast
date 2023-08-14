//
// Created by consti10 on 28.06.23.
//

#ifndef WIFIBROADCAST_WBSTREAMTX_H
#define WIFIBROADCAST_WBSTREAMTX_H

#include <queue>
#include <thread>
#include <variant>

#include "moodycamel/concurrentqueue/blockingconcurrentqueue.h"
#include "moodycamel/readerwriterqueue/readerwritercircularbuffer.h"
#include "FECStream.h"
#include "SimpleStream.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "WBTxRx.h"

/**
 * Transmitter for a (multiplexed) wifbroadcast stream
 * uses WBTxRx to send packets
 * supports enabling / disabling FEC and more
 */
class WBStreamTx {
 public:
  struct Options {
    // needs to match the radio port of the corresponding rx
    uint8_t radio_port = 0;
    // size of packet data queue
    int packet_data_queue_size=64;
    // size of block / frame data queue
    int block_data_queue_size=2;
    // Even though setting the fec_k parameter / n of primary fragments creates similar characteristics as a link
    // without fec, we have a special impl. when fec is disabled, since there we allow packets out of order and with fec_k == 1 you'd have
    // packet re-ordering / packets out of order are not possible.
    bool enable_fec= true;
    // for development, log time items spend in the data queue (it should be close to 0)
    bool log_time_spent_in_atomic_queue=false;
    // overwrite the console used for logging
    std::shared_ptr<spdlog::logger> opt_console=nullptr;
    // set sched_param = max realtime on the thread that dequeues and injects the packets
    bool dequeue_thread_max_realtime= true;
  };
  WBStreamTx(std::shared_ptr<WBTxRx> txrx,Options options);
  WBStreamTx(const WBStreamTx&) = delete;
  WBStreamTx&operator=(const WBStreamTx&) = delete;
  ~WBStreamTx();
  /**
   * Enqueue a packet to be processed. FEC needs to be disabled in this mode.
   * Guaranteed to return immediately.
   * This method is not thread-safe.
   * @param packet the packet (data) to enqueue
   * @param n_injections: This is especially for openhd telemetry - we have the issue that the telemetry uplink is incredibly lossy
   * due to the (video) tx talking over the ground telemetry tx. However, FEC is not really suited for telemetry -
   * therefore, we have a simple duplicate (aka inject the same packet more than once) feature.
   * Since the FECDisabled impl. handles packet duplicates, duplicates only increase the likeliness of a specific packet being received, and
   * are not forwarded multiple times. By default, don't do any packet duplication (1)
   * @return true on success (space in the packet queue), false otherwise
   */
  bool try_enqueue_packet(std::shared_ptr<std::vector<uint8_t>> packet,int n_injections=1);
  /**
   * Enqueue a block (most likely a frame) to be processed, FEC needs to be enabled in this mode.
   * Guaranteed to return immediately.
   * This method is not thread-safe.
   * If the n of fragments exceeds @param max_block_size, the block is split into one or more sub-blocks.
   * @return true on success (space in the block queue), false otherwise
   */
  bool try_enqueue_block(std::vector<std::shared_ptr<std::vector<uint8_t>>> fragments,int max_block_size,int fec_overhead_perc);
  // statistics
  struct Statistics{
    int64_t n_provided_packets;
    int64_t n_provided_bytes;
    int64_t n_injected_packets;
    int64_t n_injected_bytes;
    uint64_t current_provided_bits_per_second;
    uint64_t current_injected_bits_per_second;
    // Other than bits per second, packets per second is also an important metric -
    // Sending a lot of small packets for example should be avoided
    uint64_t current_injected_packets_per_second;
    // N of dropped packets, increases when both the internal driver queue and the extra 124 packets queue of the tx fill up
    uint64_t n_dropped_packets;
  };
  Statistics get_latest_stats();
  // only valid when actually doing FEC
  struct FECStats{
    MinMaxAvg<std::chrono::nanoseconds> curr_fec_encode_time{};
    MinMaxAvg<uint16_t> curr_fec_block_length{};
  };
  FECStats get_latest_fec_stats();
  /**
   * Enables / disables encryption for this stream
   * (pass encrypt=true on the inject cb)
   */
  void set_encryption(bool encrypt){
    m_enable_encryption=encrypt;
  }
 private:
  const Options options;
  std::shared_ptr<WBTxRx> m_txrx;
  std::shared_ptr<spdlog::logger> m_console;
  // On the tx, either one of those two is active at the same time
  std::unique_ptr<FECEncoder> m_fec_encoder = nullptr;
  std::unique_ptr<FECDisabledEncoder> m_fec_disabled_encoder = nullptr;
  // We have two data queues with a slightly different layout (depending on the selected operating mode)
  struct EnqueuedPacket {
    std::chrono::steady_clock::time_point enqueue_time_point=std::chrono::steady_clock::now();
    std::shared_ptr<std::vector<uint8_t>> data;
    int n_injections;
  };
  struct EnqueuedBlock {
    std::chrono::steady_clock::time_point enqueue_time_point=std::chrono::steady_clock::now();
    int max_block_size;
    int fec_overhead_perc;
    std::vector<std::shared_ptr<std::vector<uint8_t>>> fragments;
  };
  // Used if fec is disabled, for telemetry data
  std::unique_ptr<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<EnqueuedPacket>>> m_packet_queue;
  // Used if fec is enabled, for video data
  std::unique_ptr<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<EnqueuedBlock>>> m_block_queue;
  // The thread that consumes the provided packets or blocks, set to sched param realtime
  std::unique_ptr<std::thread> m_process_data_thread;
  bool m_process_data_thread_run=true;
  uint64_t m_n_dropped_packets=0;
  // Time fragments / blocks spend in the non-blocking atomic queue.
  AvgCalculator m_queue_time_calculator;
  // n of packets fed to the instance
  int64_t m_n_input_packets = 0;
  // count of bytes we got passed (aka for example, what the video encoder produced - does not include FEC)
  uint64_t m_count_bytes_data_provided =0;
  // n of actually injected packets
  int64_t m_n_injected_packets = 0;
  BitrateCalculator m_bitrate_calculator_data_provided{};
  // count of bytes we injected into the wifi card
  uint64_t m_count_bytes_data_injected =0;
  BitrateCalculator m_bitrate_calculator_injected_bytes{};
  PacketsPerSecondCalculator m_packets_per_second_calculator{};
  void loop_process_data();
  void process_enqueued_packet(const EnqueuedPacket& packet);
  void process_enqueued_block(const EnqueuedBlock& block);
  void send_packet(const uint8_t* packet,int packet_len);
  std::atomic<bool> m_enable_encryption=true;
};

#endif  // WIFIBROADCAST_WBSTREAMTX_H
