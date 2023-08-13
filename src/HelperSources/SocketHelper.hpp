//
// Created by consti10 on 21.04.22.
//

#ifndef WIFIBROADCAST_SOCKETHELPER_HPP
#define WIFIBROADCAST_SOCKETHELPER_HPP

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termio.h>
#include <unistd.h>

#include <list>
#include <mutex>
#include <optional>
#include <thread>

#include "../wifibroadcast_spdlog.h"
#include <spdlog/spdlog.h>
#include "StringHelper.hpp"
#include "TimeHelper.hpp"

namespace SocketHelper {
struct UDPConfig{
  const std::string ip;
  const int port;
};

static std::string ip_port_as_string(const std::string ip,int port){
  return ip+":"+std::to_string(port);
}

static const std::string ADDRESS_LOCALHOST = "127.0.0.1";
static const std::string ADDRESS_ANY="0.0.0.0";

// returns the current socket receive timeout
static std::chrono::nanoseconds getCurrentSocketReceiveTimeout(int socketFd) {
  timeval tv{};
  socklen_t len = sizeof(tv);
  auto res = getsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &tv, &len);
  assert(res == 0);
  assert(len == sizeof(tv));
  return MyTimeHelper::timevalToDuration(tv);
}
// set the receive timeout on the socket
// throws runtime exception if this step fails (should never fail on linux)
static void setSocketReceiveTimeout(int socketFd, const std::chrono::nanoseconds timeout) {
  const auto currentTimeout = getCurrentSocketReceiveTimeout(socketFd);
  if (currentTimeout != timeout) {
    auto tv =  MyTimeHelper::durationToTimeval(timeout);
    if (setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
      std::stringstream ss;
      ss<<"Cannot set socket timeout "<<timeout.count();
      wifibroadcast::log::get_default()->warn(ss.str());
    }
  }
}
// Set the reuse flag on the socket, so it doesn't care if there is a broken down process
// still on the socket or not.
static void setSocketReuse(int sockfd) {
  int enable = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    wifibroadcast::log::get_default()->warn("Cannot set socket reuse");
  }
}
// increase the UDP receive buffer size, needed for high bandwidth (at ~>20MBit/s the "default"
// udp receive buffer size is often not enough and the OS might (silently) drop packets on localhost)
static void increase_socket_recv_buff_size(int sockfd, const int wanted_rcvbuff_size_bytes) {
  int recvBufferSize=0;
  socklen_t len=sizeof(recvBufferSize);
  getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &recvBufferSize, &len);
  {
    std::stringstream ss;
    ss<<"Default UDP socket recv buffer size:"<<StringHelper::memorySizeReadable(recvBufferSize)<<" wanted:"<<StringHelper::memorySizeReadable(wanted_rcvbuff_size_bytes)<<"\n";
    wifibroadcast::log::get_default()->warn(ss.str());
  }
  // We never decrease the socket receive buffer size, only increase it when neccessary
  if(wanted_rcvbuff_size_bytes>(size_t)recvBufferSize){
    int wanted_size=wanted_rcvbuff_size_bytes;
    recvBufferSize=wanted_rcvbuff_size_bytes;
    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &wanted_size,len)) {
      wifibroadcast::log::get_default()->warn("Cannot increase UDP buffer size to {}",StringHelper::memorySizeReadable(wanted_rcvbuff_size_bytes));
    }
    // Fetch it again to double check
    recvBufferSize=-1;
    getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &recvBufferSize, &len);
    wifibroadcast::log::get_default()->warn("UDP Wanted {} Set {}",StringHelper::memorySizeReadable(wanted_rcvbuff_size_bytes),StringHelper::memorySizeReadable(recvBufferSize));
  }
}
// Open the specified port for udp receiving
// sets SO_REUSEADDR to true if possible
// throws a runtime exception if opening the socket fails
static int openUdpSocketForReceiving(const std::string& address,const int port) {
  int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0){
    std::stringstream ss;
    ss<<"Error opening socket "<<port<<" "<<strerror(errno)<<"\n";
    wifibroadcast::log::get_default()->warn(ss.str());
    return -1;
  }
  setSocketReuse(fd);
  struct sockaddr_in saddr{};
  bzero((char *) &saddr, sizeof(saddr));
  saddr.sin_family = AF_INET;
  //saddr.sin_addr.s_addr = htonl(INADDR_ANY);
  inet_aton(address.c_str(), (in_addr *) &saddr.sin_addr.s_addr);
  saddr.sin_port = htons((unsigned short) port);
  if (bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
    std::stringstream ss;
    ss<<"Bind error on socket "<<address.c_str()<<":"<<port<<" "<< strerror(errno)<<"\n";
    wifibroadcast::log::get_default()->warn(ss.str());
    return -1;
  }
  return fd;
}
// Wrapper around an UDP port you can send data to
// opens port on construction, closes port on destruction
class UDPForwarder {
 public:
  explicit UDPForwarder(std::string client_addr1, int client_udp_port1) :
                                                                          client_addr(std::move(client_addr1)), client_udp_port(client_udp_port1) {
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
      std::stringstream message;
      message << "Error opening socket:" << strerror(errno) << "\n";
      wifibroadcast::log::get_default()->warn(message.str());
    }
    //set up the destination
    bzero((char *) &saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    //saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
    inet_aton(client_addr.c_str(), (in_addr *) &saddr.sin_addr.s_addr);
    saddr.sin_port = htons((uint16_t) client_udp_port);
    wifibroadcast::log::get_default()->debug("UDPForwarder::configured for {} {}",client_addr,client_udp_port);
  }
  UDPForwarder(const UDPForwarder &) = delete;
  UDPForwarder &operator=(const UDPForwarder &) = delete;
  ~UDPForwarder() {
    close(sockfd);
  }
  void forwardPacketViaUDP(const uint8_t *packet, const std::size_t packetSize) const {
    //send(sockfd,packet,packetSize, MSG_DONTWAIT);
    const auto ret=sendto(sockfd, packet, packetSize, 0, (const struct sockaddr *) &saddr,
                            sizeof(saddr));
    if(ret <0 || ret != packetSize){
      wifibroadcast::log::get_default()->warn("Error sending packet of size:{} to {} code:{} {}",
                                              packetSize,ip_port_as_string(client_addr,client_udp_port),ret, strerror(errno));
    }
  }
 private:
  struct sockaddr_in saddr{};
  int sockfd;
 public:
  const std::string client_addr;
  const int client_udp_port;
};

/**
 * Similar to UDP forwarder, but allows forwarding the same data to 0 or more IP::Port tuples
 */
class UDPMultiForwarder {
 public:
  /**
  * Start forwarding data to another IP::Port tuple
   */
  void addForwarder(const std::string &client_addr, int client_udp_port) {
    std::lock_guard<std::mutex> guard(udpForwardersLock);
    // check if we already forward data to this IP::Port tuple
    for (const auto &udpForwarder: udpForwarders) {
      if (udpForwarder->client_addr == client_addr && udpForwarder->client_udp_port == client_udp_port) {
        wifibroadcast::log::get_default()->warn("UDPMultiForwarder: already forwarding to: {}:{}",client_addr,client_udp_port);
        return;
      }
    }
    wifibroadcast::log::get_default()->debug("UDPMultiForwarder: add forwarding to: {}:{}",client_addr,client_udp_port);
    udpForwarders.emplace_back(std::make_unique<SocketHelper::UDPForwarder>(client_addr, client_udp_port));
  }
  /**
  * Remove an already existing udp forwarding instance.
  * Do nothing if such an instance is not found.
   */
  void removeForwarder(const std::string &client_addr, int client_udp_port) {
    std::lock_guard<std::mutex> guard(udpForwardersLock);
    udpForwarders.erase(std::find_if(udpForwarders.begin(),
                                     udpForwarders.end(),
                                     [&client_addr, &client_udp_port](const auto &udpForwarder) {
                                       return udpForwarder->client_addr == client_addr
                                              && udpForwarder->client_udp_port == client_udp_port;
                                     }));
  }
  /**
   * Forward data to all added IP::Port tuples via UDP
   */
  void forwardPacketViaUDP(const uint8_t *packet, const std::size_t packetSize) {
    std::lock_guard<std::mutex> guard(udpForwardersLock);
    for (const auto &udpForwarder: udpForwarders) {
      udpForwarder->forwardPacketViaUDP(packet, packetSize);
    }
  }
  [[nodiscard]] const std::list<std::unique_ptr<SocketHelper::UDPForwarder>> &getForwarders() const {
    return udpForwarders;
  }
 private:
  // list of host::port tuples where we send the data to.
  std::list<std::unique_ptr<SocketHelper::UDPForwarder>> udpForwarders;
  // modifying the list of forwarders must be thread-safe
  std::mutex udpForwardersLock;
};

class UDPReceiver {
 public:
  typedef std::function<void(const uint8_t *payload, const std::size_t payloadSize)> OUTPUT_DATA_CALLBACK;
  static constexpr const size_t UDP_PACKET_MAX_SIZE = 65507;
  /**
   * Receive data from socket and forward it via callback until stopLooping() is called
   */
  explicit UDPReceiver(std::string client_addr, int client_udp_port, OUTPUT_DATA_CALLBACK cb,std::optional<int> wanted_recv_buff_size=std::nullopt)
      :mCb(std::move(cb)),m_wanted_recv_buff_size(wanted_recv_buff_size) {
    mSocket = SocketHelper::openUdpSocketForReceiving(client_addr,client_udp_port);
    if(m_wanted_recv_buff_size!=std::nullopt){
      increase_socket_recv_buff_size(mSocket,m_wanted_recv_buff_size.value());
    }
    wifibroadcast::log::get_default()->debug("UDPReceiver created with {}:{}",client_addr,client_udp_port);
  }
  ~UDPReceiver(){
    stopBackground();
  }
  void loopUntilError() {
    const auto buff = std::make_unique<std::array<uint8_t, UDP_PACKET_MAX_SIZE>>();
    //sockaddr_in source;
    //socklen_t sourceLen= sizeof(sockaddr_in);
    while (receiving) {
      //const ssize_t message_length = recvfrom(mSocket,buff->data(),UDP_PACKET_MAX_SIZE, MSG_WAITALL,(sockaddr*)&source,&sourceLen);
      const ssize_t message_length = recv(mSocket, buff->data(), buff->size(), MSG_WAITALL);
      if (message_length > 0) {
        mCb(buff->data(), (size_t) message_length);
      } else {
        // this can also come from the shutdown, in which case it is not an error.
        // But this way we break out of the loop.
        if(receiving){
          wifibroadcast::log::get_default()->warn("Got message length of: {}",message_length);
        }
      }
    }
    wifibroadcast::log::get_default()->debug("UDP end");
  }
  // Now this one is kinda special - for mavsdk we need to send messages from the port we are listening on
  // to a specific IP::PORT tuple (such that the source address of the then received packet matches the address we are listening on).
  void forwardPacketViaUDP(const std::string& destIp,const int destPort,const uint8_t *packet, const std::size_t packetSize) const {
    //set up the destination
    struct sockaddr_in saddr{};
    bzero((char *) &saddr, sizeof(saddr));
    saddr.sin_family = AF_INET;
    //saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
    inet_aton(destIp.c_str(), (in_addr *) &saddr.sin_addr.s_addr);
    saddr.sin_port = htons((uint16_t)  destPort);
    // send from the currently bound UDP port to the destination address
    const auto ret=sendto(mSocket, packet, packetSize, 0, (const struct sockaddr *) &saddr,
                            sizeof(saddr));
    if(ret <0 || ret != packetSize){
      wifibroadcast::log::get_default()->warn("Error sending packet of size:{} to {} code:{} {}",
                                              packetSize,ip_port_as_string(destIp,destPort),ret, strerror(errno));
    }
  }
  void stopLooping() {
    receiving = false;
    // from https://github.com/mavlink/MAVSDK/blob/main/src/mavsdk/core/udp_connection.cpp#L102
    shutdown(mSocket, SHUT_RDWR);
    close(mSocket);
  }
  void runInBackground() {
    if (receiverThread) {
      wifibroadcast::log::get_default()->warn("Receiver thread is already running or has not been properly stopped");
      return;
    }
    receiving= true;
    receiverThread = std::make_unique<std::thread>(&UDPReceiver::loopUntilError, this);
  }
  void stopBackground() {
    stopLooping();
    if (receiverThread && receiverThread->joinable()) {
      receiverThread->join();
    }
    receiverThread = nullptr;
  }
 private:
  const OUTPUT_DATA_CALLBACK mCb;
  bool receiving = true;
  int mSocket;
  std::unique_ptr<std::thread> receiverThread = nullptr;
  const std::optional<int> m_wanted_recv_buff_size;
};
}

#endif //WIFIBROADCAST_SOCKETHELPER_HPP
