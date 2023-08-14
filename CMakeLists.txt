cmake_minimum_required(VERSION 3.16.3)
project(Wifibroadcast)

set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize-address-use-after-scope -fsanitize=address")

include(WBLib.cmake)

add_executable(wfb_keygen executables/wfb_keygen.cpp)
target_link_libraries(wfb_keygen PRIVATE ${WB_TARGET_LINK_LIBRARIES})

add_executable(benchmark executables/benchmark.cpp)
target_link_libraries(benchmark PRIVATE ${WB_TARGET_LINK_LIBRARIES})

add_executable(udp_generator_validator executables/udp_generator_validator.cpp)
target_link_libraries(udp_generator_validator PRIVATE ${WB_TARGET_LINK_LIBRARIES})

add_executable(unit_test executables/unit_test.cpp)
target_link_libraries(unit_test PRIVATE ${WB_TARGET_LINK_LIBRARIES})

add_executable(socket_helper_test executables/socket_helper_test.cpp)
target_link_libraries(socket_helper_test PRIVATE ${WB_TARGET_LINK_LIBRARIES})

add_executable(udp_packet_drop_util executables/udp_packet_drop_util.cpp)
target_link_libraries(udp_packet_drop_util PRIVATE ${WB_TARGET_LINK_LIBRARIES})

add_executable(test_txrx executables/test_txrx.cpp)
target_link_libraries(test_txrx PRIVATE ${WB_TARGET_LINK_LIBRARIES})

add_executable(example_hello executables/example_hello.cpp)
target_link_libraries(example_hello PRIVATE ${WB_TARGET_LINK_LIBRARIES})

add_executable(example_udp executables/example_udp.cpp)
target_link_libraries(example_udp PRIVATE ${WB_TARGET_LINK_LIBRARIES})

add_executable(injection_rate_test executables/injection_rate_test.cpp)
target_link_libraries(injection_rate_test PRIVATE ${WB_TARGET_LINK_LIBRARIES})

add_executable(example_pollute executables/example_pollute.cpp)
target_link_libraries(example_pollute PRIVATE ${WB_TARGET_LINK_LIBRARIES})

# When it is a static library, we don't need to install it.
# But if it is a shared library, we need to install it.
#install(TARGETS wifibroadcast DESTINATION lib)
install(TARGETS wfb_keygen DESTINATION bin)
install(TARGETS benchmark DESTINATION bin)
install(TARGETS udp_generator_validator DESTINATION bin)
install(TARGETS unit_test DESTINATION bin)
install(TARGETS socket_helper_test DESTINATION bin)


