//
// Created by consti10 on 29.06.23.
//

#include "WBStreamRx.h"

#include <algorithm>
#include <utility>

#include "../radiotap/RadiotapHeaderTx.hpp"
#include "../radiotap/RadiotapHeaderTxHolder.hpp"
#include "SchedulingHelper.hpp"
#include "WBPacketHeader.h"

WBStreamRx::WBStreamRx(std::shared_ptr<WBTxRx> txrx, Options options1)
    : m_txrx(txrx), m_options(options1) {
  assert(m_txrx);
  if (m_options.opt_console) {
    m_console = m_options.opt_console;
  } else {
    m_console = wifibroadcast::log::create_or_get(
        "wb_rx" + std::to_string(m_options.radio_port));
  }
  if (m_options.enable_fec) {
    m_fec_decoder = std::make_unique<FECDecoder>(
        m_options.fec_rx_queue_depth, MAX_TOTAL_FRAGMENTS_PER_BLOCK,
        m_options.enable_fec_debug_log, m_options.forward_gapped_fragments);
    auto cb = [this](const uint8_t *data, int data_len) {
      on_decoded_packet(data, data_len);
    };
    m_fec_decoder->mSendDecodedPayloadCallback = cb;
  } else {
    m_fec_disabled_decoder = std::make_unique<FECDisabledDecoder>();
    auto cb = [this](const uint8_t *data, int data_len) {
      on_decoded_packet(data, data_len);
    };
    m_fec_disabled_decoder->mSendDecodedPayloadCallback = cb;
  }
  auto cb_packet = [this](uint64_t nonce, int wlan_index, const uint8_t *data,
                          const int data_len) {
    this->on_new_packet(nonce, wlan_index, data, data_len);
  };
  auto cb_sesssion = [this]() { this->on_new_session(); };
  auto handler = std::make_shared<WBTxRx::StreamRxHandler>(
      m_options.radio_port, cb_packet, cb_sesssion);
  m_txrx->rx_register_stream_handler(handler);
  if (m_options.retransmission_request_retries < 1) {
    m_retransmission_request_retries.store(1, std::memory_order_relaxed);
  } else {
    m_retransmission_request_retries.store(
        m_options.retransmission_request_retries, std::memory_order_relaxed);
  }
  if (m_options.enable_threading) {
    m_packet_queue =
        std::make_unique<PacketQueueType>(m_options.packet_queue_size);
    m_process_data_thread_run = true;
    m_process_data_thread =
        std::make_unique<std::thread>(&WBStreamRx::loop_process_data, this);
  }
}

WBStreamRx::~WBStreamRx() {
  m_txrx->rx_unregister_stream_handler(m_options.radio_port);
  if (m_options.enable_threading) {
    m_process_data_thread_run = false;
    if (m_process_data_thread->joinable()) {
      m_process_data_thread->join();
    }
  }
}

void WBStreamRx::set_callback(
    WBStreamRx::OUTPUT_DATA_CALLBACK output_data_callback) {
  m_out_cb = std::move(output_data_callback);
}

void WBStreamRx::on_new_packet(uint64_t nonce, int wlan_index,
                               const uint8_t *data, const int data_len) {
  m_n_input_packets++;
  m_n_input_bytes += data_len;
  if (m_options.enable_threading) {
    auto item = std::make_shared<EnqueuedPacket>();
    item->data = std::make_shared<std::vector<uint8_t>>(data, data + data_len);
    const bool res = m_packet_queue->try_enqueue(item);
    if (!res) {
      // would hint at too high cpu usage
      m_console->warn("Cannot enqueue packet");
    }
  } else {
    internal_process_packet(data, data_len);
  }
}

void WBStreamRx::on_new_session() {
  if (m_fec_decoder) {
    m_fec_decoder->reset_rx_queue();
  }
  if (m_fec_disabled_decoder) {
    m_fec_disabled_decoder->reset_packets_map();
  }
  reset_stream_stats();
  m_first_packet_received_by_type.fill(false);
  m_last_seq_num_by_type.fill(0);
  m_request_index_counter = 0;
}

void WBStreamRx::loop_process_data() {
  if (m_options.threading_enabled_set_max_realtime) {
    SchedulingHelper::set_thread_params_max_realtime(
        "WBStreamRx::loop_process_data", 80);
  }
  static constexpr std::int64_t timeout_usecs = 1000 * 1000;
  while (m_process_data_thread_run) {
    auto opt_packet =
        m_packet_queue->wait_dequeue_timed(std::chrono::milliseconds(100));
    if (opt_packet.has_value()) {
      auto packet = opt_packet.value();
      internal_process_packet(packet->data->data(), (int)packet->data->size());
    }
  }
}

void WBStreamRx::on_decoded_packet(const uint8_t *data, int data_len) {
  m_n_output_bytes += data_len;
  if (m_out_cb) {
    m_out_cb(data, data_len);
  }
}

WBStreamRx::Statistics WBStreamRx::get_latest_stats() {
  WBStreamRx::Statistics ret;
  ret.n_input_bytes = m_n_input_bytes;
  ret.n_input_packets = m_n_input_packets;
  ret.curr_in_packets_per_second =
      m_input_packets_per_second_calculator.get_last_or_recalculate(
          m_n_input_packets, std::chrono::seconds(2));
  ret.curr_in_bits_per_second =
      m_input_bitrate_calculator.get_last_or_recalculate(
          m_n_input_bytes, std::chrono::seconds(2));
  ret.curr_out_bits_per_second =
      m_received_bitrate_calculator.get_last_or_recalculate(
          m_n_output_bytes, std::chrono::seconds(2));
  ret.curr_missing_packets_per_second =
      m_missing_packets_per_second_calculator.get_last_or_recalculate(
          m_n_missing_packets.load(), std::chrono::seconds(2));
  ret.curr_retransmission_requests_per_second =
      m_retransmission_requests_per_second_calculator.get_last_or_recalculate(
          m_n_retransmission_requests.load(), std::chrono::seconds(2));
  ret.curr_retransmission_packets_per_second =
      m_retransmission_packets_per_second_calculator.get_last_or_recalculate(
          m_n_retransmission_packets.load(), std::chrono::seconds(2));
  return ret;
}

WBStreamRx::FECRxStats2 WBStreamRx::get_latest_fec_stats() {
  WBStreamRx::FECRxStats2 ret;
  if (m_fec_decoder) {
    auto stats = m_fec_decoder->stats;
    ret.count_blocks_lost = stats.count_blocks_lost;
    ret.count_blocks_recovered = stats.count_blocks_recovered;
    ret.count_blocks_total = stats.count_blocks_total;
    ret.count_fragments_recovered = stats.count_fragments_recovered;
    ret.curr_fec_decode_time = stats.curr_fec_decode_time;
  }
  return ret;
}

void WBStreamRx::reset_stream_stats() {
  m_n_input_bytes = 0;
  m_n_input_packets = 0;
  m_n_output_bytes.store(0, std::memory_order_relaxed);
  m_n_missing_packets.store(0, std::memory_order_relaxed);
  m_n_retransmission_requests.store(0, std::memory_order_relaxed);
  m_n_retransmission_packets.store(0, std::memory_order_relaxed);
  m_first_packet_received_by_type.fill(false);
  m_last_seq_num_by_type.fill(0);
  m_request_index_counter = 0;
}

void WBStreamRx::set_on_fec_block_done_cb(WBStreamRx::ON_BLOCK_DONE_CB cb) {
  m_fec_decoder->m_block_done_cb = cb;
}

void WBStreamRx::set_retransmission_request_retries(int retries) {
  if (retries < 1) {
    retries = 1;
  }
  m_retransmission_request_retries.store(retries, std::memory_order_relaxed);
}

void WBStreamRx::internal_process_packet(const uint8_t *data, int data_len) {
  // Strip WBPacketHeader if present
  if (data_len < (int)sizeof(WBPacketHeader)) {
    m_console->debug("Packet too short for header: {}", data_len);
    return;
  }

  const WBPacketHeader *header = (const WBPacketHeader *)data;
  const uint8_t *payload = data + sizeof(WBPacketHeader);
  int payload_len = data_len - sizeof(WBPacketHeader);

  // Handle Retransmission Request (if we are the TX side listening to RX side
  // requests) NOTE: This logic is usually on the TX side. But if we reuse
  // WBStreamRx for receiving telemetry on AIR, we might see this. However,
  // WBStreamTx logic added previously handles listening for requests.
  // WBStreamRx is primarily for receiving data.

  if (header->packet_type == WB_PACKET_TYPE_RETRANSMISSION_REQ) {
    // This is a request. If we are an RX stream, we shouldn't really receive
    // this unless we are debugging or in a loopback. Or if this WBStreamRx is
    // used on the Air Unit to receive Uplink data, and the Uplink data contains
    // Retransmission Requests. But typically Retransmission Requests are
    // handled by the callback registered in WBStreamTx.
    return;
  }

  if ((header->packet_flags & WB_PACKET_FLAG_RETRANSMITTED) &&
      is_retransmission_enabled_for_packet_type(header->packet_type)) {
    m_console->debug("Received retransmitted packet, seq: {}",
                     header->stream_packet_idx);
    m_n_retransmission_packets.fetch_add(1, std::memory_order_relaxed);
  }

  // Gap detection
  check_gap_and_request(header->packet_type, header->stream_packet_idx);

  if (m_options.enable_fec) {
    if (!FECDecoder::validate_packet_size(payload_len)) {
      m_console->debug("invalid fec packet size {}", payload_len);
      return;
    }
    m_fec_decoder->process_valid_packet(payload, payload_len);
  } else {
    m_fec_disabled_decoder->process_packet(payload, payload_len);
  }
}

void WBStreamRx::check_gap_and_request(uint8_t packet_type,
                                       uint32_t current_seq_num) {
  if (!m_options.enable_retransmission) {
    return;
  }
  if (!m_first_packet_received_by_type[packet_type]) {
    m_first_packet_received_by_type[packet_type] = true;
    m_last_seq_num_by_type[packet_type] = current_seq_num;
    return;
  }

  // Handle wrap-around using int32_t logic
  uint32_t last_seq = m_last_seq_num_by_type[packet_type];
  int32_t diff = (int32_t)(current_seq_num - last_seq);

  if (diff > 1) {
    // Gap detected
    // Limit number of requests or range to avoid flooding
    uint32_t missing_count = diff - 1;
    if (missing_count > 10)
      missing_count = 10;  // Cap at 10 to avoid huge bursts

    if (is_retransmission_enabled_for_packet_type(packet_type)) {
      m_n_missing_packets.fetch_add(missing_count, std::memory_order_relaxed);
      const int retries = std::max(
          1, m_retransmission_request_retries.load(std::memory_order_relaxed));
      for (uint32_t i = 1; i <= missing_count; i++) {
        uint32_t missing_seq = last_seq + i;
        m_console->debug("Detected gap. Requesting seq: {}", missing_seq);
        for (int r = 0; r < retries; r++) {
          send_retransmission_request(packet_type, missing_seq);
        }
      }
    }
  }

  // Update last sequence number
  // Handle reordered packets? If current < last (diff <= 0), we might have
  // received an old packet (or retransmission).
  if (diff > 0) {
    m_last_seq_num_by_type[packet_type] = current_seq_num;
  }
}

void WBStreamRx::send_retransmission_request(uint8_t packet_type,
                                             uint32_t seq_num) {
  m_n_retransmission_requests.fetch_add(1, std::memory_order_relaxed);
  // Construct packet
  WBPacketHeader header;
  header.packet_type = WB_PACKET_TYPE_RETRANSMISSION_REQ;
  header.packet_flags = 0;
  header.stream_packet_idx =
      seq_num;  // Use this field to convey the requested sequence number
  header.total_length =
      sizeof(WBPacketHeader) + sizeof(uint8_t) + sizeof(uint16_t);

  // Create buffer (header + requested packet type + request index)
  std::vector<uint8_t> packet(sizeof(WBPacketHeader) + sizeof(uint8_t) +
                              sizeof(uint16_t));
  memcpy(packet.data(), &header, sizeof(WBPacketHeader));
  packet[sizeof(WBPacketHeader)] = packet_type;
  const uint16_t request_index = m_request_index_counter++;
  memcpy(packet.data() + sizeof(WBPacketHeader) + sizeof(uint8_t),
         &request_index, sizeof(uint16_t));

  // Send using WBTxRx
  // Need a RadiotapHeaderTx. We can use a default one or create one.
  // WBTxRx::tx_inject_packet requires a RadiotapHeaderTx.
  // We can't easily get one here without storing it or creating a default.
  // Let's create a default one.

  // Need a RadiotapHeaderTx.
  RadiotapHeaderTx::UserSelectableParams params{};
  // Default params usually fine for control packets
  params.bandwidth = 20;
  params.mcs_index = 0;  // Low MCS for reliability

  RadiotapHeaderTx radiotap_header(params);

  // Use m_options.radio_port for sending?
  m_txrx->tx_inject_packet(m_options.radio_port, packet.data(), packet.size(),
                           radiotap_header, false);
}

bool WBStreamRx::is_retransmission_enabled_for_packet_type(
    uint8_t packet_type) const {
  if (!m_options.enable_retransmission) return false;
  if (m_options.retransmission_packet_type_mask == 0) {
    return true;
  }
  return (m_options.retransmission_packet_type_mask & (1u << packet_type)) != 0;
}
