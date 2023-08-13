//
// Created by consti10 on 14.11.22.
//

#ifndef WIFIBROADCAST_SRC_WIFIBROADCAST_SPDLOG_H_
#define WIFIBROADCAST_SRC_WIFIBROADCAST_SPDLOG_H_

#include "wifibroadcast-spdlog2.h"

/*#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <mutex>

namespace wifibroadcast::log{

static std::shared_ptr<spdlog::logger> create_or_get(const std::string& logger_name){
  static std::mutex logger_mutex2{};
  std::lock_guard<std::mutex> guard(logger_mutex2);
  auto ret = spdlog::get(logger_name);
  if (ret == nullptr) {
    auto created = spdlog::stdout_color_mt(logger_name);
    created->set_level(spdlog::level::debug);
    assert(created);
    return created;
  }
  return ret;
}

static std::shared_ptr<spdlog::logger> get_default() {
  return create_or_get("wifibroadcast");
}

}*/
#endif  // WIFIBROADCAST_SRC_WIFIBROADCAST_SPDLOG_H_
