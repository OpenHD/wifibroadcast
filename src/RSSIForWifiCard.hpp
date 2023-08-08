//
// Created by consti10 on 30.06.23.
//

#ifndef WIFIBROADCAST_RSSIFORWIFICARD_HPP
#define WIFIBROADCAST_RSSIFORWIFICARD_HPP

#include "TimeHelper.hpp"

/**
 * Helper to accumulate RSSI values
 */
class RSSIAccumulator{
 public:
  void add_rssi(int8_t rssi){
    if(rssi<=INT8_MIN || rssi>=0){
      // RSSI should always be negative and in range [-127,-1]
      wifibroadcast::log::get_default()->debug("Invalid rssi {}",rssi);
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
  std::string get_min_max_avg_readable(bool avg_only= false){
    MinMaxAvg<int> tmp{get_min(),get_max(),get_avg()};
    return min_max_avg_as_string(tmp, avg_only);
  }
  int get_n_samples(){
    return m_rssi_count;
  }
  std::optional<MinMaxAvg<int8_t>> add_and_recalculate_if_needed(int8_t rssi){
    add_rssi(rssi);
    if(get_n_samples()>=10){
      auto tmp=get_min_max_avg();
      reset();
      return tmp;
    }
  }
  void reset(){
    m_rssi_sum=0;
    m_rssi_count=0;
    m_rssi_min=INT8_MAX;
    m_rssi_max=INT8_MIN;
  }
 private:
  int m_rssi_sum=0;
  int m_rssi_count=0;
  int8_t m_rssi_min=INT8_MAX;
  int8_t m_rssi_max=INT8_MIN;
};


// Stores the min, max and average of the rssi values reported for this wifi card
// Doesn't differentiate from which antenna the rssi value came
//https://www.radiotap.org/fields/Antenna%20signal.html
class RSSIForWifiCard {
 public:
  RSSIForWifiCard() = default;

  void addRSSI(int8_t rssi) {
    m_rssi_acc.add_rssi(rssi);
    if(m_rssi_acc.get_n_samples()>=10){
      wifibroadcast::log::get_default()->debug("{}",m_rssi_acc.get_min_max_avg_readable());
      m_rssi_acc.reset();
    }
    last_rssi=rssi;
    if (count_all == 0) {
      rssi_min = rssi;
      rssi_max = rssi;
    } else {
      rssi_min = std::min(rssi, rssi_min);
      rssi_max = std::max(rssi, rssi_max);
    }
    rssi_sum += rssi;
    count_all += 1;
  }
  int8_t getAverage() const {
    if (rssi_sum == 0)return INT8_MIN;
    return rssi_sum / count_all;
  }
  void reset() {
    count_all = 0;
    rssi_sum = 0;
    rssi_min = 0;
    rssi_max = 0;
  }
  int32_t count_all = 0;
  int32_t rssi_sum = 0;
  int8_t rssi_min = 0;
  int8_t rssi_max = 0;
  int8_t last_rssi=INT8_MIN;
 public:
  RSSIAccumulator m_rssi_antenna1{};
  RSSIAccumulator m_rssi_antenna2{};
};
static std::ostream& operator<<(std::ostream& strm, const RSSIForWifiCard& obj){
  std::stringstream ss;
  ss<<"RSSIForWifiCard{last:"<<(int)obj.last_rssi<<",avg:"<<(int)obj.getAverage()<<",min:"<<(int)obj.rssi_min
     <<",max:"<<(int)obj.rssi_max<<"}";
  strm<<ss.str();
  return strm;
}

#endif  // WIFIBROADCAST_RSSIFORWIFICARD_HPP
