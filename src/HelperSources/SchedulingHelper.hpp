//
// Created by consti10 on 20.12.20.
//

#ifndef WIFIBROADCAST_SCHEDULINGHELPER_H
#define WIFIBROADCAST_SCHEDULINGHELPER_H

#include <pthread.h>
#include <sys/resource.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "../wifibroadcast_spdlog.h"
#include <spdlog/spdlog.h>

namespace SchedulingHelper {
static void printCurrentThreadPriority(const std::string& name) {
  int which = PRIO_PROCESS;
  id_t pid = (id_t) getpid();
  int priority = getpriority(which, pid);
  wifibroadcast::log::get_default()->debug("{} has priority {}",name,priority);
}

static void printCurrentThreadSchedulingPolicy(const std::string& name) {
  auto self = pthread_self();
  int policy;
  sched_param param{};
  auto result = pthread_getschedparam(self, &policy, &param);
  if (result != 0) {
    wifibroadcast::log::get_default()->warn( "Cannot get thread scheduling policy");
  }
  wifibroadcast::log::get_default()->debug("{} has policy {} and priority {}",name,policy,param.sched_priority);
}

// this thread should run as close to realtime as possible
static void setThreadParamsMaxRealtime(pthread_t target) {
  int policy = SCHED_FIFO;
  sched_param param{};
  param.sched_priority = sched_get_priority_max(policy);
  auto result = pthread_setschedparam(target, policy, &param);
  if (result != 0) {
    wifibroadcast::log::get_default()->warn("cannot set ThreadParamsMaxRealtime");
  }
}

static void setThreadParamsMaxRealtime() {
  setThreadParamsMaxRealtime(pthread_self());
}

static bool check_root() {
  const auto uid = getuid();
  const bool root = uid ? false : true;
  return root;
}

}
#endif //WIFIBROADCAST_SCHEDULINGHELPER_H
