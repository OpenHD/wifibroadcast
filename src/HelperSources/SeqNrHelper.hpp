//
// Created by consti10 on 21.12.22.
//

#ifndef WIFIBROADCAST_SRC_HELPERSOURCES_SEQNRHELPER_H_
#define WIFIBROADCAST_SRC_HELPERSOURCES_SEQNRHELPER_H_

#include <atomic>
#include <cmath>
#include <memory>

#include "../wifibroadcast_spdlog.h"
#include <spdlog/spdlog.h>


// UINT16SeqNrHelper for calculating statistics for a link with a rolling (wrap around) uint16_t sequence number
class UINT16SeqNrHelper {
 public:
  UINT16SeqNrHelper(){
    m_gaps.reserve(MAX_N_STORED_GAPS);
    m_curr_packet_loss=-1;
  }
  void reset(){
    m_last_seq_nr=-1;
    //m_curr_packet_loss=-1;
    //m_curr_gaps_counter=-1;
  }
  int16_t get_current_loss_percent(){
    return m_curr_packet_loss;
  }
  int16_t get_current_gaps_counter(){
    return m_curr_gaps_counter;
  }
  void on_new_sequence_number(uint16_t seq_nr){
    if(m_last_seq_nr==-1){
      // first ever packet
      m_last_seq_nr=seq_nr;
      return;
    }
    const auto diff=diff_between_packets_rolling_uint16_t(m_last_seq_nr, seq_nr);
    if(diff>1){
      const auto gap_size=diff-1;
      // as an example, a diff of 2 means one packet is missing.
      m_n_missing_packets+=gap_size;
      m_n_received_packets++;
      // can be usefully for debugging
      if(m_store_and_debug_gaps && gap_size>1){
        store_debug_gap(gap_size);
      }
      //store_gap(diff-1);
      //m_console->debug("Diff:{}",diff);
      store_gap2(diff);
    }else{
      m_n_received_packets++;
    }
    m_last_seq_nr=seq_nr;
    recalculate_loss_if_needed();
  }
  void set_store_and_debug_gaps(bool enable){
    m_store_and_debug_gaps=enable;
  }
 private:
  // recalculate the loss in percentage in fixed intervals
  // resets the received and missing packet count
  void recalculate_loss_if_needed(){
    if(std::chrono::steady_clock::now()-m_last_loss_perc_recalculation>std::chrono::seconds(2)){
      m_last_loss_perc_recalculation=std::chrono::steady_clock::now();
      const auto n_total_packets=m_n_received_packets+m_n_missing_packets;
      //m_console->debug("x_n_missing_packets:{} x_n_received_packets:{} n_total_packets:{}",x_n_missing_packets,x_n_received_packets,n_total_packets);
      if(n_total_packets>=1){
        const double loss_perc=static_cast<double>(m_n_missing_packets)/static_cast<double>(n_total_packets)*100.0;
        //m_curr_packet_loss=static_cast<int16_t>(std::lround(loss_perc));
        // we always round up the packet loss
        m_curr_packet_loss=static_cast<int16_t>(std::ceil(loss_perc));
        //wifibroadcast::log::get_default()->debug("Packet loss:{} % {} %",m_curr_packet_loss,loss_perc);
      }else{
        // We did not get any packets in the last x seconds
        m_curr_packet_loss=-1;
      }
      m_n_received_packets=0;
      m_n_missing_packets=0;
    }
  }
  void store_debug_gap(int gap_size){
    m_gaps.push_back(gap_size);
    const auto elasped=std::chrono::steady_clock::now()-m_last_gap_log;
    if(elasped>std::chrono::seconds(1) || m_gaps.size()>=MAX_N_STORED_GAPS){
      wifibroadcast::log::get_default()->debug("Gaps: {}",StringHelper::vectorAsString(m_gaps));
      m_gaps.resize(0);
      m_last_gap_log=std::chrono::steady_clock::now();
    }
  }
  void store_gap2(int gap_size){
    if(gap_size>=GAP_SIZE_COUNTS_AS_BIG_GAP){
      m_n_big_gaps++;
    }
    const auto elapsed=std::chrono::steady_clock::now()-m_last_big_gaps_counter_recalculation;
    if(elapsed>=std::chrono::seconds(1)){
      m_curr_gaps_counter=(int16_t)m_n_big_gaps;
      m_n_big_gaps=0;
      m_last_big_gaps_counter_recalculation=std::chrono::steady_clock::now();
    }
  }
  static int diff_between_packets_rolling_uint16_t(int last_packet,int curr_packet){
    if(last_packet==curr_packet){
      wifibroadcast::log::get_default()->debug("Duplicate in seq nr {}-{}, invalid usage",last_packet,curr_packet);
    }
    if(curr_packet<last_packet){
      // We probably have overflown the uin16_t range
      const auto diff=curr_packet+UINT16_MAX+1-last_packet;
      return diff;
    }else{
      return curr_packet-last_packet;
    }
  }
 private:
  int m_last_seq_nr=-1;
  static constexpr int MAX_N_STORED_GAPS=1000;
  std::vector<int> m_gaps;
  static constexpr int GAP_SIZE_COUNTS_AS_BIG_GAP=10;
 private:
  int m_n_received_packets=0;
  int m_n_missing_packets=0;
  int m_n_big_gaps=0;
  std::chrono::steady_clock::time_point m_last_gap_log;
  std::chrono::steady_clock::time_point m_last_loss_perc_recalculation=std::chrono::steady_clock::now();
  std::chrono::steady_clock::time_point m_last_big_gaps_counter_recalculation=std::chrono::steady_clock::now();
  std::atomic<int16_t> m_curr_packet_loss{};
  std::atomic<int16_t> m_curr_gaps_counter{};
  bool m_store_and_debug_gaps= false;
};

#endif  // WIFIBROADCAST_SRC_HELPERSOURCES_SEQNRHELPER_H_
