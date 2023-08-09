//
// Created by consti10 on 30.06.23.
//

#ifndef WIFIBROADCAST_RSSIACCUMULATOR_HPP
#define WIFIBROADCAST_RSSIACCUMULATOR_HPP

#include <optional>

#include "TimeHelper.hpp"
#include "wifibroadcast-spdlog.h"

/**
 * Helper to accumulate RSSI values
 */
class RSSIAccumulator{
 public:
  void add_rssi(int8_t rssi){
    if(rssi<=INT8_MIN || rssi>=0){
      // RSSI should always be negative and in range [-127,-1]
      // It seems to be quite common for drivers to report invalid rssi values from time to time - in this case,
      // just ignore the value
      if(m_debug_invalid_rssi){
        wifibroadcast::log::get_default()->debug("Invalid rssi on id {}, {}",m_rssi_identifier,rssi);
      }
      return ;
    }
    if(rssi>m_rssi_max){
      m_rssi_max=rssi;
    }
    if(rssi<m_rssi_min){
      m_rssi_min=rssi;
    }
    m_rssi_sum+=static_cast<int>(rssi);
    m_rssi_count++;
  }
  int8_t get_avg()const{
    const auto count=m_rssi_count;
    if(count<=0)return INT8_MIN;
    const auto avg=m_rssi_sum/m_rssi_count;
    return static_cast<int8_t>(avg);
  }
  int8_t get_min()const{
    if(m_rssi_count<=0)return INT8_MIN;
    return m_rssi_min;
  }
  int8_t get_max()const{
    if(m_rssi_count<=0)return INT8_MIN;
    return m_rssi_max;
  }
  MinMaxAvg<int8_t> get_min_max_avg(){
    MinMaxAvg<int8_t> tmp{get_min(),get_max(),get_avg()};
    return tmp;
  }
  static std::string min_max_avg_to_string(const MinMaxAvg<int8_t>& data,bool avg_only= false){
    // Need to convert to int such that it is shown correctly
    MinMaxAvg<int> tmp{data.min,data.max,data.avg};
    return min_max_avg_as_string(tmp, avg_only);
  }
  int get_n_samples(){
    return m_rssi_count;
  }
  std::optional<MinMaxAvg<int8_t>> add_and_recalculate_if_needed(int8_t rssi){
    add_rssi(rssi);
    // Calculate every 20 packets or 500ms and at least one packet, whatever is reached first
    const auto elapsed=std::chrono::steady_clock::now()-m_last_recalculation;
    if(get_n_samples()>=20 || (get_n_samples()>=1 && elapsed>=std::chrono::milliseconds(500))){
      auto tmp=get_min_max_avg();
      reset();
      m_last_recalculation=std::chrono::steady_clock::now();
      return tmp;
    }
    return std::nullopt;
  }
  void reset(){
    m_rssi_sum=0;
    m_rssi_count=0;
    m_rssi_min=INT8_MAX;
    m_rssi_max=INT8_MIN;
  }
  void set_debug_invalid_rssi(bool enable,int rssi_identifier){
    m_debug_invalid_rssi=enable;
    m_rssi_identifier=rssi_identifier;
  }
 private:
  int m_rssi_sum=0;
  int m_rssi_count=0;
  int8_t m_rssi_min=INT8_MAX;
  int8_t m_rssi_max=INT8_MIN;
  std::chrono::steady_clock::time_point m_last_recalculation=std::chrono::steady_clock::now();
  bool m_debug_invalid_rssi= false;
  int m_rssi_identifier=0;
};

#endif  // WIFIBROADCAST_RSSIACCUMULATOR_HPP
