//
// Created by consti10 on 07.01.24.
//

#include "DummyLink.h"

#include <fcntl.h>
#include <memory.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "SchedulingHelper.hpp"
#include "SocketHelper.hpp"

// From
// http://www.atakansarioglu.com/linux-ipc-inter-process-messaging-linux-domain-socket-fifo-pipe-shared-memory-shm-example/

static sockaddr_un create_adr(const std::string& name) {
  // Unix domain socket file address.
  struct sockaddr_un address;
  address.sun_family = AF_UNIX;
  strcpy(address.sun_path, name.c_str());
  return address;
}

static int create_socket_read(const std::string& name) {
  auto address = create_adr(name);
  // Delete the old socket file.
  unlink(name.c_str());
  // Create a unix domain socket.
  int fd;
  if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    std::cout << "Receiver: Cannot create socket" << std::endl;
    return -1;
  }

  // Bind the socket to the address.
  if (bind(fd, (struct sockaddr*)&address, sizeof(sockaddr_un)) != 0) {
    std::cout << "Receiver: Cannot bind socket" << std::endl;
    return -1;
  }
  return fd;
}

static int create_socket_send() {
  // Create a unix domain socket.
  int fd;
  if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    std::cout << "Sender: Cannot create socket" << std::endl;
    return -1;
  }
  return fd;
}

static void send_data(int fd, const std::string& name, const uint8_t* data,
                      int data_len) {
  auto address = create_adr(name);
  if (sendto(fd, data, data_len, 0, (struct sockaddr*)&address,
             sizeof(sockaddr_un)) != data_len) {
    // std::cout << "Client: Cannot send" << std::endl;
  }
  // std::cout<<"Sent:"<<data_len<<std::endl;
}

static constexpr auto MAX_MTU_INCLUDING_HEADER = 2000;

DummyLink::DummyLink(bool is_air) : m_is_air(is_air) {
  if (m_is_air) {
    m_fn_tx = "air";
    m_fn_rx = "gnd";
    // m_fn_rx="air";
  } else {
    m_fn_tx = "gnd";
    m_fn_rx = "air";
  }
  m_fd_rx = create_socket_read(m_fn_rx);
  SocketHelper::set_socket_send_rcv_timeout(
      m_fd_rx, std::chrono::milliseconds(1000), true);
  m_fd_tx = create_socket_send();
  m_rx_queue = std::make_unique<RxPacketQueueType>(1000);
  m_keep_receiving = true;
  m_receive_thread = std::make_unique<std::thread>(&DummyLink::loop_rx, this);
}

DummyLink::~DummyLink() {
  m_keep_receiving = false;
  shutdown(m_fd_rx, SHUT_RDWR);
  close(m_fd_rx);
  m_receive_thread->join();
  m_receive_thread = nullptr;
  close(m_fd_tx);
}

void DummyLink::tx_radiotap(const uint8_t* packet_buff, int packet_size) {
  const bool drop = should_drop_packet();
  if (!drop) {
    send_data(m_fd_tx, m_fn_tx, packet_buff, packet_size);
  }
}

std::shared_ptr<std::vector<uint8_t>> DummyLink::rx_radiotap() {
  std::shared_ptr<DummyLink::RxPacket> packet = nullptr;
  static constexpr std::int64_t timeout_usecs = 100 * 1000;
  auto opt_packet =
      m_rx_queue->wait_dequeue_timed(std::chrono::milliseconds(100));
  if (opt_packet.has_value()) {
    // dequeued frame
    return opt_packet.value()->buff;
  }
  return nullptr;
}

void DummyLink::loop_rx() {
  SchedulingHelper::set_thread_params_max_realtime("DummyLink::loop_rx");
  auto read_buffer =
      std::make_shared<std::vector<uint8_t>>(MAX_MTU_INCLUDING_HEADER);
  while (m_keep_receiving) {
    // auto packet= read_data(m_fd_rx);
    // auto size=recvfrom(fd, buff->data(), buff->size(), MSG_DONTWAIT, NULL,
    // NULL);
    auto size =
        recv(m_fd_rx, read_buffer->data(), read_buffer->size(), MSG_WAITALL);
    if (size > 0) {
      auto packet = std::make_shared<std::vector<uint8_t>>(
          read_buffer->data(), read_buffer->data() + size);
      // std::cout<<"Got packet"<<packet->size()<<std::endl;
      auto item = std::make_shared<DummyLink::RxPacket>();
      item->buff = packet;
      const auto success = m_rx_queue->try_enqueue(item);
      if (!success) {
        // Should never happen
      }
    }
    // std::cout<<"ARGH"<<std::endl;
  }
}

bool DummyLink::should_drop_packet() {
  if (m_drop_mode == 0) return false;
  int rand = next_random_number_0_100();
  if (rand <= m_drop_mode) {
    return true;
  }
  return false;
}

void DummyLink::set_drop_mode(int drop_mode) { m_drop_mode = drop_mode; }
