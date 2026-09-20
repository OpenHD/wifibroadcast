#ifndef EMULATEDPACKETDROP_H
#define EMULATEDPACKETDROP_H

#include <cstdlib>
#include <ctime>
#include <mutex>
#include <random>

// emulating packet drop "as" when using wifibroadcast (no matter weather it is
// with or without FEC) is not that easy.

// Drops a specific percentage of packets, this doesn't eumlate the "big gaps"
// behaviour
class PacketDropEmulator {
 public:
  PacketDropEmulator(int percentage_dropped_packets)
      : m_percentage_dropped_packets(percentage_dropped_packets) {}
  // Returns true if you should drop this packet, false otherwise
  bool drop_packet() {
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto number = next_random_number_0_100();
    // qDebug()<<"Number is:"<<number;
    n_totoal_packets++;
    if (m_percentage_dropped_packets > number) {
      // drop packet
      n_dropped_packets++;
      log();
      return true;
    }
    n_forwarded_packets++;
    log();
    return false;
  }
  void log() {
    const double perc_dropped =
        (double)n_dropped_packets / (n_totoal_packets) * 100.0;
    // std::cout<<"N
    // dropped:"<<n_dropped_packets<<",forwarded:"<<n_forwarded_packets<<"Perc:"<<perc_dropped<<"\n";
  }
  void set_new_percentage(int new_perc) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_percentage_dropped_packets = new_perc;
  }

 private:
  std::mutex m_mutex;
  int m_percentage_dropped_packets;
  int n_dropped_packets = 0;
  int n_forwarded_packets = 0;
  int n_totoal_packets = 0;
  int next_random_number_0_100() { return m_dist100(m_mt); }
  std::mt19937 m_mt;
  std::uniform_int_distribution<> m_dist100{0, 100};
};

#endif  // EMULATEDPACKETDROP_H
