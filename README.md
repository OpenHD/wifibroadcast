# Summary
c++ Library for wifibroadcast video and telemetry streaming. \
## Features
1) Multiplexing and packet validation / encryption
2) Zero latency overhead FEC video streaming (requires usage of c++)
3) SIMD accelerated FEC (NEON on ARM, SSSE3 on x86)
4) Advanced debugging and statistics (e.g. packet loss) [see](https://github.com/OpenHD/wifibroadcast/blob/master/src/WBTxRx.h#L121)
5) Simple examples to get started
6) Basic unit tests for FEC

# Getting started
## Compiling
run sudo ./install_dep.sh \
Compile with cmake (./build_cmake.sh)

## Examples
NOTE: You need to first enable monitor mode on your card(s) and the card driver
needs to support active and passive monitor mode (listening & injecting packets)
1) example_hello: [link](https://github.com/OpenHD/wifibroadcast/blob/master/executables/example_hello.cpp) \
    Bidirectional communication between air and ground unit 
2) benchmark: [link](https://github.com/OpenHD/wifibroadcast/blob/master/executables/benchmark.cpp) \
    Gives a quick overview over FEC and encryption / decryption performance on your platform 
3) example_udp: [link](https://github.com/OpenHD/wifibroadcast/blob/master/executables/example_udp.cpp) \
    Simple unidirectional UDP streaming application, can be used for
    rapid development and shows how you could create your own WB link with 
    multiple unidirectional / bidirectional streams 
### For a more practical application, please check out OpenHD EVO !
[Project](https://github.com/OpenHD/OpenHD/blob/2.3-evo/OpenHD/ohd_interface/inc/wb_link.h#L31)

[Link implementation](https://github.com/OpenHD/OpenHD/blob/2.3-evo/OpenHD/ohd_interface/inc/wb_link.h#L31)

### Pre unify tx / rx
The design principle of running multiple instances of an application (e.g. wifibroadcast tx / rx) 
has a couple of disadvantages.
It makes debugging quite hard (you now have multiple applications for video tx, video rx, and telemetry tx, telemetry rx),
makes threading and sequencing harder and also increases latency on the tx with the udp & rtp approach.
Doing more in c++ and less scripting makes it easy to solve those issues.
However, if you want to use scripting / udp badly, checkout [pre-unify-tx-rx](https://github.com/OpenHD/wifibroadcast/tree/pre-unify-tx-rx)
