//
// Created by consti10 on 05.12.20.
//

#ifndef WIFIBROADCAST_SOCKETHELPER_H
#define WIFIBROADCAST_SOCKETHELPER_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <string.h>
#include <utime.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <endian.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sodium.h>
#include <endian.h>
#include <string>
#include <vector>
#include <chrono>
#include <stdarg.h>
#include <chrono>
//
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <termio.h>
#include <sys/ioctl.h>
#include <net/if.h>

// For all the stuff that was once in wifibroadcast.hpp

namespace StringFormat{
    static std::string convert(const char *format, ...){
        va_list args;
        va_start(args, format);
        size_t size = vsnprintf(nullptr, 0, format, args) + 1; // Extra space for '\0'
        va_end(args);
        std::unique_ptr<char[]> buf(new char[size]);
        va_start(args, format);
        vsnprintf(buf.get(), size, format, args);
        va_end(args);
        return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
    }
}

namespace GenericHelper{
    static void fillBufferWithRandomData(std::vector<uint8_t>& data){
        const std::size_t size=data.size();
        for(std::size_t i=0;i<size;i++){
            data[i] = rand() % 255;
        }
    }
    // Create a buffer filled with random data of size sizeByes
    std::vector<uint8_t> createRandomDataBuffer(const ssize_t sizeBytes){
        std::vector<uint8_t> buf(sizeBytes);
        fillBufferWithRandomData(buf);
        return buf;
    }
    bool compareVectors(const std::vector<uint8_t>& sb,const std::vector<uint8_t>& rb){
        if(sb.size()!=rb.size()){
            return false;
        }
        const int result=memcmp (sb.data(),rb.data(),sb.size());
        return result==0;
    }
    using namespace std::chrono;
    constexpr nanoseconds timevalToDuration(timeval tv){
        auto duration = seconds{tv.tv_sec}
                        + microseconds {tv.tv_usec};
        return duration_cast<nanoseconds>(duration);
    }
    constexpr time_point<system_clock, nanoseconds>
    timevalToTimePointSystemClock(timeval tv){
        return time_point<system_clock, nanoseconds>{
                duration_cast<system_clock::duration>(timevalToDuration(tv))};
    }
    constexpr time_point<steady_clock, nanoseconds>
    timevalToTimePointSteadyClock(timeval tv){
        return time_point<steady_clock, nanoseconds>{
                duration_cast<steady_clock::duration>(timevalToDuration(tv))};
    }
    constexpr timeval durationToTimeval(nanoseconds dur){
        const auto secs = duration_cast<seconds>(dur);
        dur -= secs;
        const auto us=duration_cast<microseconds>(dur);
        return timeval{secs.count(), us.count()};
    }
}

namespace SocketHelper{
    // originally in wifibroadcast.cpp/ h
    // I thought it might be a good idea to have all these helpers inside their own namespace
    static int open_udp_socket(const std::string &client_addr, int client_port) {
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(StringFormat::convert("Error opening socket: %s", strerror(errno)));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short) client_port);

        if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
            throw std::runtime_error(StringFormat::convert("Connect error: %s", strerror(errno)));
        }
        return fd;
    }
    static int open_udp_socket_for_tx(const std::string &client_addr, int client_port) {
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(StringFormat::convert("Error opening socket: %s", strerror(errno)));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(client_addr.c_str());
        saddr.sin_port = htons((unsigned short) client_port);

        if (connect(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
            throw std::runtime_error(StringFormat::convert("Connect error: %s", strerror(errno)));
        }
        return fd;
    }
    static int open_udp_socket_for_rx(int port){
        struct sockaddr_in saddr;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error(StringFormat::convert("Error opening socket: %s", strerror(errno)));

        int optval = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = htonl(INADDR_ANY);
        saddr.sin_port = htons((unsigned short)port);

        if (bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
        {
            throw std::runtime_error(StringFormat::convert("Bind error: %s", strerror(errno)));
        }
        return fd;
    }
    // Open the specified port for udp receiving
    // sets SO_REUSEADDR
    // sets timeout if if it is not 0
    static int openUdpSocketForRx(const int port,std::chrono::nanoseconds timeout=std::chrono::nanoseconds(0)){
        int fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0) throw std::runtime_error(StringFormat::convert("Error opening socket %d: %s",port, strerror(errno)));
        int enable = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
            //throw std::runtime_error(StringFormat::convert("Error setting reuse on socket %d: %s",port, strerror(errno)));
            // don't crash here
            std::cout<<"Cannot set socket reuse\n";
        }
        if(timeout!=std::chrono::nanoseconds(0)){
            auto tv=GenericHelper::durationToTimeval(timeout);
            if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
                std::cout<<"Cannot set socket timeout "<<timeout.count()<<"\n";
            }
        }
        struct sockaddr_in saddr{};
        bzero((char *) &saddr, sizeof(saddr));
        saddr.sin_family = AF_INET;
        saddr.sin_addr.s_addr = htonl(INADDR_ANY);
        saddr.sin_port = htons((unsigned short)port);
        if (bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0){
            throw std::runtime_error(StringFormat::convert("Bind error on socket %d: %s",port, strerror(errno)));
        }
        return fd;
    }
    ///  taken from https://github.com/OpenHD/Open.HD/blob/2.0/wifibroadcast-base/tx_rawsock.c#L86
    // open wifi interface using a socket (somehow this works ?!)
    static int openWifiInterfaceAsTx(std::string wifi) {
        struct sockaddr_ll ll_addr{};
        struct ifreq ifr{};
        int sock = socket(AF_PACKET, SOCK_RAW, 0);
        if (sock == -1) {
            throw std::runtime_error(StringFormat::convert("Socket failed %s %s",wifi.c_str(),strerror(errno)));
        }

        ll_addr.sll_family = AF_PACKET;
        ll_addr.sll_protocol = 0;
        ll_addr.sll_halen = ETH_ALEN;

        strncpy(ifr.ifr_name, wifi.c_str(), IFNAMSIZ);

        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            throw std::runtime_error(StringFormat::convert("ioctl(SIOCGIFINDEX) failed\n"));
        }

        ll_addr.sll_ifindex = ifr.ifr_ifindex;

        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            throw std::runtime_error(StringFormat::convert("ioctl(SIOCGIFHWADDR) failed\n"));
        }

        memcpy(ll_addr.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

        if (bind(sock, (struct sockaddr *)&ll_addr, sizeof(ll_addr)) == -1) {
            close(sock);
            throw std::runtime_error("bind failed\n");
        }
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 8000;
        if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
            throw std::runtime_error("setsockopt SO_SNDTIMEO\n");
        }
        int sendbuff = 131072;
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff)) < 0) {
            throw std::runtime_error("setsockopt SO_SNDBUF\n");
        }
        return sock;
    }
}



#endif //WIFIBROADCAST_SOCKETHELPER_H
