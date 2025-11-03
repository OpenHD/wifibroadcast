cmake_minimum_required(VERSION 3.16.3)
project(Wifibroadcast)

set(CMAKE_CXX_STANDARD 20)

# --- Dependencies ---
find_package(PkgConfig REQUIRED)

# libpcap
pkg_check_modules(PCAP REQUIRED libpcap)
include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})

# libsodium
pkg_check_modules(SODIUM REQUIRED libsodium)
include_directories(${SODIUM_INCLUDE_DIRS})
link_directories(${SODIUM_LIBRARY_DIRS})

# spdlog
find_package(spdlog REQUIRED)

# WBLib (internal project CMake)
set(WB_USE_SPDLOG_EXTERNALLY OFF)
include(wifibroadcast/WBLib.cmake)

# --- Executables ---
add_executable(wfb_keygen wifibroadcast/executables/wfb_keygen.cpp)
target_link_libraries(wfb_keygen PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(benchmark wifibroadcast/executables/benchmark.cpp)
target_link_libraries(benchmark PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(udp_generator_validator wifibroadcast/executables/udp_generator_validator.cpp)
target_link_libraries(udp_generator_validator PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(unit_test wifibroadcast/executables/unit_test.cpp)
target_link_libraries(unit_test PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(socket_helper_test wifibroadcast/executables/socket_helper_test.cpp)
target_link_libraries(socket_helper_test PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(udp_packet_drop_util wifibroadcast/executables/udp_packet_drop_util.cpp)
target_link_libraries(udp_packet_drop_util PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(test_txrx wifibroadcast/executables/test_txrx.cpp)
target_link_libraries(test_txrx PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(example_hello wifibroadcast/executables/example_hello.cpp)
target_link_libraries(example_hello PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(example_udp wifibroadcast/executables/example_udp.cpp)
target_link_libraries(example_udp PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(injection_rate_test wifibroadcast/executables/injection_rate_test.cpp)
target_link_libraries(injection_rate_test PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(example_pollute wifibroadcast/executables/example_pollute.cpp)
target_link_libraries(example_pollute PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(test_listen wifibroadcast/executables/test_listen.cpp)
target_link_libraries(test_listen PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(test_dummy_link wifibroadcast/executables/test_dummy_link.cpp)
target_link_libraries(test_dummy_link PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

add_executable(test_queue wifibroadcast/executables/test_queue.cpp)
target_link_libraries(test_queue PRIVATE ${WB_TARGET_LINK_LIBRARIES} ${PCAP_LIBRARIES} ${SODIUM_LIBRARIES} spdlog::spdlog)

# Only install library if it's built as shared
if (TARGET wifibroadcast)
    get_target_property(WB_TYPE wifibroadcast TYPE)
    if (WB_TYPE STREQUAL "SHARED_LIBRARY")
        message(STATUS "Installing shared library: wifibroadcast")
        install(TARGETS wifibroadcast DESTINATION lib)
    else()
        message(STATUS "Skipping install for static library: wifibroadcast")
    endif()
endif()

# --- Install targets ---
install(TARGETS
    wfb_keygen
    benchmark
    udp_generator_validator
    unit_test
    socket_helper_test
    example_hello
    example_udp
    udp_packet_drop_util
    test_txrx
    injection_rate_test
    example_pollute
    test_listen
    test_dummy_link
    test_queue
    DESTINATION bin
)
