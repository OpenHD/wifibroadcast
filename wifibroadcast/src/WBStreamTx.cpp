//
// Created by consti10 on 28.06.23.
//

#include "WBStreamTx.h"

#include <utility>
#include <cstring>
#include <algorithm>

#include "BlockSizeHelper.hpp"
#include "SchedulingHelper.hpp"

WBStreamTx::WBStreamTx(
    std::shared_ptr<WBTxRx> txrx, Options options1,
    std::shared_ptr<RadiotapHeaderTxHolder> radiotap_header_holder)
    : options(options1),
      m_txrx(txrx),
      m_radiotap_header_holder(std::move(radiotap_header_holder)) {
  assert(m_txrx);
  if (options.opt_console) {
    m_console = options.opt_console;
  } else {
    m_console = wifibroadcast::log::create_or_get(
        "wb_tx" + std::to_string(options.radio_port));
  }
  assert(m_console);
  m_console->info("WBTransmitter radio_port: {} fec:{} retransmission:{}", options.radio_port,
                  options.enable_fec ? "Y" : "N", options.enable_retransmission ? "Y" : "N");
  if (options.enable_fec) {
    // m_block_queue=std::make_unique<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<EnqueuedBlock>>>(options.block_data_queue_size);
    m_block_queue =
        std::make_unique<BlockQueueType>(options.block_data_queue_size);
    m_fec_encoder = std::make_unique<FECEncoder>();
    auto cb = [this](const uint8_t* packet, int packet_len) {
      // Determine packet type based on FEC enablement - Video usually uses FEC
      prepare_and_send_packet(packet, packet_len, WB_PACKET_TYPE_VIDEO);
    };
    m_fec_encoder->m_out_cb = cb;
  } else {
    // m_packet_queue=std::make_unique<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<EnqueuedPacket>>>(options.packet_data_queue_size);
    m_packet_queue =
        std::make_unique<PacketQueueType>(options.packet_data_queue_size);
    m_fec_disabled_encoder = std::make_unique<FECDisabledEncoder>();
    auto cb = [this](const uint8_t* packet, int packet_len) {
        // Telemetry usually doesn't use FEC
      prepare_and_send_packet(packet, packet_len, WB_PACKET_TYPE_TELEMETRY);
    };
    m_fec_disabled_encoder->outputDataCallback = cb;
  }
  m_process_data_thread_run = true;
  m_process_data_thread =
      std::make_unique<std::thread>(&WBStreamTx::loop_process_data, this);
}

WBStreamTx::~WBStreamTx() {
  m_process_data_thread_run = false;
  if (m_process_data_thread && m_process_data_thread->joinable()) {
    m_process_data_thread->join();
  }
}

bool WBStreamTx::try_enqueue_packet(
    std::shared_ptr<std::vector<uint8_t>> packet, int n_injections) {
  assert(!options.enable_fec);
  m_n_input_packets++;
  m_count_bytes_data_provided += packet->size();
  auto item = std::make_shared<EnqueuedPacket>();
  item->data = std::move(packet);
  item->n_injections = n_injections;
  const bool res = m_packet_queue->try_enqueue(item);
  if (!res) {
    m_n_dropped_packets++;
  }
  return res;
}

int WBStreamTx::enqueue_packet_dropping(
    std::shared_ptr<std::vector<uint8_t>> packet, int n_injections) {
  assert(!options.enable_fec);
  m_n_input_packets++;
  m_count_bytes_data_provided += packet->size();
  auto item = std::make_shared<EnqueuedPacket>();
  item->data = std::move(packet);
  item->n_injections = n_injections;
  const int n_dropped = m_packet_queue->enqueue_or_clear_enqueue(item);
  if (n_dropped > 0) {
    m_n_dropped_packets += n_dropped;
  }
  return n_dropped;
}

bool WBStreamTx::try_enqueue_block(
    std::vector<std::shared_ptr<std::vector<uint8_t>>> fragments,
    int max_block_size, int fec_overhead_perc,
    std::chrono::steady_clock::time_point creation_time) {
  assert(options.enable_fec);
  m_n_input_packets += fragments.size();
  for (const auto& fragment : fragments) {
    if (fragment->empty() || fragment->size() > FEC_PACKET_MAX_PAYLOAD_SIZE) {
      m_console->warn("Fed fragment with incompatible size:{}",
                      fragment->size());
      return false;
    }
    m_count_bytes_data_provided += fragment->size();
  }
  auto item = std::make_shared<EnqueuedBlock>();
  item->fragments = fragments;
  item->max_block_size = max_block_size;
  item->fec_overhead_perc = fec_overhead_perc;
  item->creation_time = creation_time;
  const bool res = m_block_queue->try_enqueue(item);
  if (!res) {
    m_n_dropped_packets += fragments.size();
    m_n_dropped_frames++;
    // m_curr_seq_nr+=fragments.size();
  }
  return res;
}

int WBStreamTx::enqueue_block_dropping(
    std::vector<std::shared_ptr<std::vector<uint8_t>>> fragments,
    int max_block_size, int fec_overhead_perc,
    std::chrono::steady_clock::time_point creation_time) {
  assert(options.enable_fec);
  m_n_input_packets += fragments.size();
  for (const auto& fragment : fragments) {
    if (fragment->empty() || fragment->size() > FEC_PACKET_MAX_PAYLOAD_SIZE) {
      m_console->warn("Fed fragment with incompatible size:{}",
                      fragment->size());
      return false;
    }
    m_count_bytes_data_provided += fragment->size();
  }
  auto item = std::make_shared<EnqueuedBlock>();
  item->fragments = fragments;
  item->max_block_size = max_block_size;
  item->fec_overhead_perc = fec_overhead_perc;
  item->creation_time = creation_time;
  const int ret = m_block_queue->enqueue_or_clear_enqueue(item);
  if (ret != 0) {
    m_n_dropped_packets += fragments.size();
    m_n_dropped_frames += ret;
  }
  return ret;
}

bool WBStreamTx::try_enqueue_frame(
    std::shared_ptr<std::vector<uint8_t>> frame, int max_block_size,
    int fec_overhead_perc,
    std::chrono::steady_clock::time_point creation_time) {
  assert(options.enable_fec);
  m_n_input_packets += 1;
  m_count_bytes_data_provided += frame->size();
  auto item = std::make_shared<EnqueuedBlock>();
  item->frame = frame;
  item->max_block_size = max_block_size;
  item->fec_overhead_perc = fec_overhead_perc;
  item->creation_time = creation_time;
  const bool res = m_block_queue->try_enqueue(item);
  if (!res) {
    m_n_dropped_packets += 1;
    m_n_dropped_frames++;
    // m_curr_seq_nr+=fragments.size();
  }
  return res;
}

WBStreamTx::FECStats WBStreamTx::get_latest_fec_stats() {
  WBStreamTx::FECStats ret{};
  if (m_fec_encoder) {
    ret.curr_fec_encode_time = m_fec_encoder->m_curr_fec_block_encode_time;
    ret.curr_fec_block_length = m_fec_encoder->m_curr_fec_block_sizes;
  }
  return ret;
}

WBStreamTx::Statistics WBStreamTx::get_latest_stats() {
  WBStreamTx::Statistics ret{};
  ret.n_provided_bytes = m_count_bytes_data_provided;
  ret.n_provided_packets = m_n_input_packets;
  ret.n_injected_packets = m_n_injected_packets;
  ret.n_injected_bytes = static_cast<int64_t>(m_count_bytes_data_injected);
  ret.current_injected_bits_per_second =
      m_bitrate_calculator_injected_bytes.get_last_or_recalculate(
          m_count_bytes_data_injected, std::chrono::seconds(2));
  ret.current_provided_bits_per_second =
      m_bitrate_calculator_data_provided.get_last_or_recalculate(
          m_count_bytes_data_provided, std::chrono::seconds(2));
  ret.n_dropped_packets = m_n_dropped_packets;
  ret.n_dropped_frames = m_n_dropped_frames;
  ret.current_injected_packets_per_second =
      m_packets_per_second_calculator.get_last_or_recalculate(
          m_n_injected_packets, std::chrono::seconds(2));
  ret.curr_block_until_tx_min_us = m_curr_block_until_tx_min_max_avg_us.min;
  ret.curr_block_until_tx_max_us = m_curr_block_until_tx_min_max_avg_us.max;
  ret.curr_block_until_tx_avg_us = m_curr_block_until_tx_min_max_avg_us.avg;
  return ret;
}

void WBStreamTx::loop_process_data() {
  if (options.dequeue_thread_max_realtime) {
    SchedulingHelper::set_thread_params_max_realtime(
        "WBStreamTx::loop_process_data");
  }
  static constexpr std::int64_t timeout_usecs = 100 * 1000;
  if (options.enable_fec) {
    while (m_process_data_thread_run) {
      auto opt_frame =
          m_block_queue->wait_dequeue_timed(std::chrono::milliseconds(100));
      if (opt_frame.has_value()) {
        auto frame = opt_frame.value();
        // dequeued frame
        m_queue_time_calculator.add(std::chrono::steady_clock::now() -
                                    frame->enqueue_time_point);
        if (m_queue_time_calculator.get_delta_since_last_reset() >
            std::chrono::seconds(1)) {
          if (options.log_time_spent_in_atomic_queue) {
            m_console->debug("Time in queue {}",
                             m_queue_time_calculator.getAvgReadable());
          }
          m_queue_time_calculator.reset();
        }
        process_enqueued_block(*frame);
        const auto delta =
            std::chrono::steady_clock::now() - frame->creation_time;
        m_block_until_tx_time.add(delta);
        if (m_block_until_tx_time.get_delta_since_last_reset() >
            std::chrono::seconds(2)) {
          if (options.log_time_blocks_until_tx) {
            m_console->debug("Time until tx {}",
                             m_block_until_tx_time.getAvgReadable());
          }
          m_curr_block_until_tx_min_max_avg_us =
              min_max_avg_as_us(m_block_until_tx_time.getMinMaxAvg());
          m_block_until_tx_time.reset();
        }
      }
    }
  } else {
    std::shared_ptr<EnqueuedPacket> packet;
    while (m_process_data_thread_run) {
      auto opt_packet =
          m_packet_queue->wait_dequeue_timed(std::chrono::milliseconds(100));
      if (opt_packet.has_value()) {
        auto packet = opt_packet.value();
        m_queue_time_calculator.add(std::chrono::steady_clock::now() -
                                    packet->enqueue_time_point);
        if (m_queue_time_calculator.get_delta_since_last_reset() >
            std::chrono::seconds(1)) {
          if (options.log_time_spent_in_atomic_queue) {
            m_console->debug("Time in queue {}",
                             m_queue_time_calculator.getAvgReadable());
          }
          m_queue_time_calculator.reset();
        }
        process_enqueued_packet(*packet);
      }
    }
  }
}

void WBStreamTx::process_enqueued_packet(
    const WBStreamTx::EnqueuedPacket& packet) {
  auto buff = m_fec_disabled_encoder->encode_packet_buffer(packet.data->data(),
                                                           packet.data->size());
  for (int i = 0; i < packet.n_injections; i++) {
    prepare_and_send_packet(buff.data(), buff.size(), WB_PACKET_TYPE_TELEMETRY);
  }
  // m_fec_disabled_encoder->encode_packet_cb(packet.data->data(),packet.data->size());
}

void WBStreamTx::process_enqueued_block(
    const WBStreamTx::EnqueuedBlock& block) {
  if (block.frame != nullptr) {
    dirty_process_enqueued_frame(block);
    return;
  }
  auto blocks =
      blocksize::split_frame_if_needed(block.fragments, block.max_block_size);
  for (auto& x_block : blocks) {
    const auto n_secondary_f = calculate_n_secondary_fragments(
        x_block.size(), block.fec_overhead_perc);
    m_fec_encoder->encode_block(x_block, n_secondary_f);
  }
}

void WBStreamTx::dirty_process_enqueued_frame(
    const WBStreamTx::EnqueuedBlock& block) {
  // TODO: Figure out the ideal fragment size for this frame
  const int MTU = 1440;
  const int n_primary_fragments = blocksize::div_ceil(block.frame->size(), MTU);
  const int n_secondary_fragments = calculate_n_secondary_fragments(
      n_primary_fragments, block.fec_overhead_perc);
  m_fec_encoder->fragment_and_encode(block.frame->data(), block.frame->size(),
                                     n_primary_fragments,
                                     n_secondary_fragments);
}

void WBStreamTx::send_packet(const uint8_t* packet, int packet_len) {
  const auto radiotap_header = m_radiotap_header_holder->thread_safe_get();
  const bool encrypt = m_enable_encryption.load();
  m_txrx->tx_inject_packet(options.radio_port, packet, packet_len,
                           radiotap_header, encrypt);
  m_n_injected_packets++;
  m_count_bytes_data_injected += packet_len;
}

void WBStreamTx::prepare_and_send_packet(const uint8_t* data, int len, uint8_t packet_type) {
    // Construct new packet with WBPacketHeader
    size_t new_len = sizeof(WBPacketHeader) + len;
    std::vector<uint8_t> new_packet(new_len);

    WBPacketHeader* header = (WBPacketHeader*)new_packet.data();
    header->packet_type = packet_type;
    header->packet_flags = 0;

    {
        std::lock_guard<std::mutex> lock(m_history_mutex);
        header->stream_packet_idx = m_current_sequence_number++;
        header->total_length = new_len;
        // Simple CRC placeholder or calculation could go here
        header->uCRC = 0;

        memcpy(new_packet.data() + sizeof(WBPacketHeader), data, len);

        // Store in history if retransmission is enabled
        if (options.enable_retransmission) {
            SentPacket sent;
            sent.sequence_number = header->stream_packet_idx;
            sent.data = new_packet;
            sent.packet_type = packet_type;
            sent.timestamp = std::chrono::steady_clock::now();

            m_sent_packets_history.push_back(sent);
            if (m_sent_packets_history.size() > MAX_HISTORY_SIZE) {
                m_sent_packets_history.pop_front();
            }
        }
    }

    send_packet(new_packet.data(), new_packet.size());
}

void WBStreamTx::process_retransmission_request(uint32_t sequence_number) {
    if (!options.enable_retransmission) return;

    std::lock_guard<std::mutex> lock(m_history_mutex);
    for (const auto& packet : m_sent_packets_history) {
        if (packet.sequence_number == sequence_number) {
            // Found packet, re-send it
            // We need to modify the flags to indicate retransmission
            // Copy data to modify
            std::vector<uint8_t> retransmit_data = packet.data;
            WBPacketHeader* header = (WBPacketHeader*)retransmit_data.data();
            header->packet_flags |= WB_PACKET_FLAG_RETRANSMITTED;

            send_packet(retransmit_data.data(), retransmit_data.size());
            return;
        }
    }
}

int WBStreamTx::get_tx_queue_available_size_approximate() {
  // const auto ret=options.enable_fec ? m_block_queue->size_approx() :
  // m_packet_queue->size_approx(); return (int)ret;
  if (options.enable_fec) return m_block_queue->get_current_size();
  return m_packet_queue->get_current_size();
}
