//
// Created by consti10 on 30.06.23.
//

#ifndef WIFIBROADCAST_RSSIFORWIFICARD_HPP
#define WIFIBROADCAST_RSSIFORWIFICARD_HPP

// Stores the min, max and average of the rssi values reported for this wifi card
// Doesn't differentiate from which antenna the rssi value came
//https://www.radiotap.org/fields/Antenna%20signal.html
class RSSIForWifiCard {
 public:
  RSSIForWifiCard() = default;
  void addRSSI(int8_t rssi) {
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
};
static std::ostream& operator<<(std::ostream& strm, const RSSIForWifiCard& obj){
  std::stringstream ss;
  ss<<"RSSIForWifiCard{last:"<<(int)obj.last_rssi<<",avg:"<<(int)obj.getAverage()<<",min:"<<(int)obj.rssi_min
     <<",max:"<<(int)obj.rssi_max<<"}";
  strm<<ss.str();
  return strm;
}

#endif  // WIFIBROADCAST_RSSIFORWIFICARD_HPP
