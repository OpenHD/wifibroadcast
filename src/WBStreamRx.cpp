//
// Created by consti10 on 29.06.23.
//

#include "WBStreamRx.h"

#include <utility>

WBStreamRx::WBStreamRx(std::shared_ptr<WBTxRx> txrx,Options options1)
    : m_txrx(txrx),
      m_options(options1)
{
  assert(m_txrx);
  if(m_options.opt_console){
    m_console=m_options.opt_console;
  }else{
    m_console=wifibroadcast::log::create_or_get("wb_rx"+std::to_string(m_options.radio_port));
  }
  if(m_options.enable_fec){
    m_fec_decoder = std::make_unique<FECDecoder>(m_options.fec_rx_queue_depth,MAX_TOTAL_FRAGMENTS_PER_BLOCK,m_options.enable_fec_debug_log);
    auto cb=[this](const uint8_t *data, int data_len){
      on_decoded_packet(data,data_len);
    };
    m_fec_decoder->mSendDecodedPayloadCallback = cb;
  }else{
    m_fec_disabled_decoder = std::make_unique<FECDisabledDecoder>();
    auto cb=[this](const uint8_t *data, int data_len){
      on_decoded_packet(data,data_len);
    };
    m_fec_disabled_decoder->mSendDecodedPayloadCallback = cb;
  }
  auto cb_packet=[this](uint64_t nonce,int wlan_index,const uint8_t *data, const int data_len){
    this->on_new_packet(nonce,wlan_index,data,data_len);
  };
  auto cb_sesssion=[this](){
    this->on_new_session();
  };
  auto handler=std::make_shared<WBTxRx::StreamRxHandler>(m_options.radio_port,cb_packet,cb_sesssion);
  m_txrx->rx_register_stream_handler(handler);
  if(m_options.enable_threading){
    m_packet_queue=std::make_unique<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<EnqueuedPacket>>>(m_options.packet_queue_size);
    m_process_data_thread_run=true;
    m_process_data_thread=std::make_unique<std::thread>(&WBStreamRx::loop_process_data, this);
  }
}

WBStreamRx::~WBStreamRx() {
  m_txrx->rx_unregister_stream_handler(m_options.radio_port);
  if(m_options.enable_threading){
    m_process_data_thread_run= false;
    if(m_process_data_thread->joinable()){
      m_process_data_thread->join();
    }
  }
}

void WBStreamRx::set_callback(
    WBStreamRx::OUTPUT_DATA_CALLBACK output_data_callback) {
  m_out_cb=std::move(output_data_callback);
}

void WBStreamRx::on_new_packet(uint64_t nonce, int wlan_index, const uint8_t *data,const int data_len) {
  m_n_input_packets++;
  m_n_input_bytes+=data_len;
  if(m_options.enable_threading){
    auto item=std::make_shared<EnqueuedPacket>();
    item->data=std::make_shared<std::vector<uint8_t>>(data,data+data_len);
    const bool res= m_packet_queue->try_enqueue(item);
    if(!res){
      // would hint at too high cpu usage
      m_console->warn("Cannot enqueue packet");
    }
  }else{
    if(m_options.enable_fec){
      if(!FECDecoder::validate_packet_size(data_len)){
        m_console->debug("invalid fec packet size {}",data_len);
        return ;
      }
      m_fec_decoder->process_valid_packet(data,data_len);
    }else{
      m_fec_disabled_decoder->process_packet(data,data_len);
    }
  }
}

void WBStreamRx::on_new_session() {
  if(m_fec_decoder){
    m_fec_decoder->reset_rx_queue();
  }
  reset_stream_stats();
}

void WBStreamRx::loop_process_data() {
  std::shared_ptr<EnqueuedPacket> packet;
  static constexpr std::int64_t timeout_usecs=1000*1000;
  while (m_process_data_thread_run) {
    if (m_packet_queue->wait_dequeue_timed(packet, timeout_usecs)) {
      process_queued_packet(*packet);
    }
  }
}

void WBStreamRx::process_queued_packet(const WBStreamRx::EnqueuedPacket &packet) {
  assert(m_options.enable_threading== true);
  if(m_options.enable_fec){
    if(!FECDecoder::validate_packet_size(packet.data->size())){
      m_console->debug("invalid fec packet size {}",packet.data->size());
      return ;
    }
    m_fec_decoder->process_valid_packet(packet.data->data(),packet.data->size());
  }else{
    m_fec_disabled_decoder->process_packet(packet.data->data(),packet.data->size());
  }
}

void WBStreamRx::on_decoded_packet(const uint8_t *data, int data_len) {
  m_n_output_bytes+=data_len;
  if(m_out_cb){
    m_out_cb(data,data_len);
  }
}

WBStreamRx::Statistics WBStreamRx::get_latest_stats() {
  WBStreamRx::Statistics ret;
  ret.n_input_bytes=m_n_input_bytes;
  ret.n_input_packets=m_n_input_packets;
  ret.curr_in_packets_per_second=
      m_input_packets_per_second_calculator.get_last_or_recalculate(
          m_n_input_packets,std::chrono::seconds(2));
  ret.curr_in_bits_per_second=m_input_bitrate_calculator.get_last_or_recalculate(
      m_n_input_bytes,std::chrono::seconds(2));
  ret.curr_out_bits_per_second=m_received_bitrate_calculator.get_last_or_recalculate(
      m_n_output_bytes,std::chrono::seconds(2));
  return ret;
}

WBStreamRx::FECRxStats2 WBStreamRx::get_latest_fec_stats() {
  WBStreamRx::FECRxStats2 ret;
  if(m_fec_decoder){
    auto stats=m_fec_decoder->stats;
    ret.count_blocks_lost= stats.count_blocks_lost;
    ret.count_blocks_recovered=stats.count_blocks_recovered;
    ret.count_blocks_total=stats.count_blocks_total;
    ret.count_fragments_recovered=stats.count_fragments_recovered;
    ret.curr_fec_decode_time=stats.curr_fec_decode_time;
  }
  return ret;
}

void WBStreamRx::reset_stream_stats() {
  m_n_input_bytes=0;
  m_n_input_packets=0;
}
