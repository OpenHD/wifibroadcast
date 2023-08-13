//
// Created by consti10 on 13.08.23.
//

#ifndef WIFIBROADCAST_WIFIBROADCAST_SPDLOG_FAKE_H
#define WIFIBROADCAST_WIFIBROADCAST_SPDLOG_FAKE_H

#include <memory>
#include <string>

namespace fmt{

template <typename... T>
static std::string format(const std::string& unused1, T&&... args){
  return "";
}

template <typename... T>
static void print(const std::string& unused1, T&&... args){

}

}

namespace spdlog{

class logger{
 public:
  template<typename... Args>
  void debug(const std::string& unused1, Args &&...args){

  }

  template<typename... Args>
  void warn(const std::string& unused1, Args &&...args){

  };

  template<typename... Args>
  void info(const std::string& unused1, Args &&...args){

  };

  template<typename... Args>
  void error(const std::string& unused1, Args &&...args){

  };

};

}

namespace wifibroadcast::log{

static std::shared_ptr<spdlog::logger> create_or_get(const std::string& logger_name){
  return std::make_shared<spdlog::logger>();
}

static std::shared_ptr<spdlog::logger> get_default() {
  return create_or_get("wifibroadcast");
}

}


#endif  // WIFIBROADCAST_WIFIBROADCAST_SPDLOG_FAKE_H
