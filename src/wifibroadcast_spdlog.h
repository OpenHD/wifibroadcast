//
// Created by consti10 on 14.11.22.
//

#ifndef WIFIBROADCAST_SRC_WIFIBROADCAST_SPDLOG_H_
#define WIFIBROADCAST_SRC_WIFIBROADCAST_SPDLOG_H_

//#include "wifibroadcast-spdlog-fake.h"

//#include <spdlog/sinks/stdout_color_sinks.h>
//#include <spdlog/spdlog.h>
#include <spdlog/fwd.h>
#include <memory>

namespace wifibroadcast::log{

std::shared_ptr<spdlog::logger> create_or_get(const std::string& logger_name);

std::shared_ptr<spdlog::logger> get_default();

}
#endif  // WIFIBROADCAST_SRC_WIFIBROADCAST_SPDLOG_H_
