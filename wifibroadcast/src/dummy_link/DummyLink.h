//
// Created by consti10 on 07.01.24.
//

#ifndef OPENHD_DUMMYLINK_H
#define OPENHD_DUMMYLINK_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "../FunkyQueue.h"

// TODO: Write something that emulates a wb link (tx, rx)
// using linux shm or similar
class DummyLink {
 public:
  explicit DummyLink(bool is_air);
  ~DummyLink();
  void tx_radiotap(const uint8_t* packet_buff, int packet_size);
  std::shared_ptr<std::vector<uint8_t>> rx_radiotap();
  void set_drop_mode(int drop_mode);

 private:
  const bool m_is_air;
  int m_fd_tx;
  int m_fd_rx;
  std::string m_fn_tx;
  std::string m_fn_rx;
  std::unique_ptr<std::thread> m_receive_thread;
  void loop_rx();
  bool m_keep_receiving = true;
  // Drop packets with a probability of 5%
  bool should_drop_packet();
  int next_random_number_0_100() { return m_dist100(m_mt); }
  std::mt19937 m_mt;
  std::uniform_int_distribution<> m_dist100{0, 100};
  struct RxPacket {
    std::shared_ptr<std::vector<uint8_t>> buff;
  };
  using RxPacketQueueType = FunkyQueue<std::shared_ptr<RxPacket>>;
  std::unique_ptr<RxPacketQueueType> m_rx_queue;
  std::atomic_int m_drop_mode = 0;
};

#endif  // OPENHD_DUMMYLINK_H
