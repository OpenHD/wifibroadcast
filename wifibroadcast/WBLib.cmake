#
# Defines WB_TARGET_LINK_LIBRARIES
# which can then be used to integrate wifibroadcast into your project

option(WB_ENABLE_SIMD_OPTIMIZATIONS "Enable NEON on ARM and SSSE3 on X86 if the platform/compiler supports it" ON)
option(WB_USE_SPDLOG_EXTERNALLY "Do not find and link to spdlog installed on system" ON)
#if(WIFIBROADCAST_LIBRARIES_ALREADY_BUILD)
#if(get_property(source_list GLOBAL PROPERTY source_list_property))
#    message(STATUS "WIFIBROADCAST_LIBRARIES_ALREADY_BUILD")
#    return()
#endif()
if (TARGET wifibroadcast)
    message(STATUS "WIFIBROADCAST_LIBRARIES_ALREADY_BUILD")
    return()
endif()

add_library(wifibroadcast STATIC) # initialized below
add_library(wifibroadcast::wifibroadcast ALIAS wifibroadcast)
#target_compile_options(wifibroadcast INTERFACE -Wno-address-of-packed-member -Wno-cast-align)

# the stuff in lib is a bit extra
target_sources(wifibroadcast PRIVATE
        # radiotap and fec
        ${CMAKE_CURRENT_LIST_DIR}/lib/radiotap/radiotap.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/fec/fec_base.cpp
)

# Well, let's just build everything together
target_sources(wifibroadcast PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src/encryption/KeyPair.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/encryption/Encryptor.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/encryption/Encryption.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/encryption/EncryptionFsUtils.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/encryption/Decryptor.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/encryption/ExternalCryptoPlugin.cpp
        ##
        ${CMAKE_CURRENT_LIST_DIR}/src/dummy_link/DummyLink.cpp

        ${CMAKE_CURRENT_LIST_DIR}/src/fec/FEC.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/fec/FECConstants.hpp
        ${CMAKE_CURRENT_LIST_DIR}/src/fec/FECDecoder.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/fec/FECEncoder.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/fec/RxBlock.cpp

        ${CMAKE_CURRENT_LIST_DIR}/src/WBStreamRx.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/WBStreamTx.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/WBVideoStreamTx.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/WBTxRx.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/FunkyQueue.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/wifibroadcast_spdlog.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/radiotap/RadiotapRxRfAggregator.cpp
)

if(TARGET devourer)
    target_sources(wifibroadcast PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src/devourer/DevourerTransport.cpp)
    target_compile_definitions(wifibroadcast PUBLIC
        WIFIBROADCAST_WITH_DEVOURER=1)
    # Devourer and wifibroadcast both embed a radiotap iterator. Keep the
    # wifibroadcast copy private so both static libraries can be linked into
    # the same OpenHD executable without exporting duplicate C symbols.
    target_compile_definitions(wifibroadcast PRIVATE
        ieee80211_radiotap_iterator_init=wifibroadcast_radiotap_iterator_init
        ieee80211_radiotap_iterator_next=wifibroadcast_radiotap_iterator_next)
    target_link_libraries(wifibroadcast PUBLIC devourer)
endif()

target_include_directories(wifibroadcast PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/HelperSources
        ${CMAKE_CURRENT_LIST_DIR}/../../../inc
)

## FEC Optimizations begin ---------------------------------
set(WIFIBROADCAST_FEC_OPTIMIZATION_FLAGS_X86_SSSE3 -mssse3 -faligned-new=256)
set(WIFIBROADCAST_FEC_OPTIMIZATION_FLAGS_ARM_NEON -mfpu=neon -march=armv7-a -marm)
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-mssse3" COMPILER_SUPPORTS_X86_SSSE3)
# ARMv7 might not support neon - we have to ask (and set some flags)
check_cxx_compiler_flag("-mfpu=neon" COMPILER_SUPPORTS_NEON)
# ARMv8 always supports ASIMD which is a superset of NEON. No flags needed, just compile.
if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64")
    set(COMPILER_SUPPORTS_ASIMD true)
else ()
    set(COMPILER_SUPPORTS_ASIMD false)
endif ()


# SSSE3 if supported and option WB_ENABLE_SIMD_OPTIMIZATIONS is true
if(COMPILER_SUPPORTS_X86_SSSE3)
    message(STATUS "Compiler supports SSSE3")
    if(WB_ENABLE_SIMD_OPTIMIZATIONS)
        message(STATUS "WB compile with SSSE3")
        target_compile_options(wifibroadcast PUBLIC ${WIFIBROADCAST_FEC_OPTIMIZATION_FLAGS_X86_SSSE3})
        # I do not know why, but using target_compile_options seems to be not enough ...
        add_compile_options(${WIFIBROADCAST_FEC_OPTIMIZATION_FLAGS_X86_SSSE3})
        target_compile_definitions(wifibroadcast PUBLIC WIFIBROADCAST_HAS_X86_SSSE3)
    endif()
endif()
# NEON if supported and option WB_ENABLE_SIMD_OPTIMIZATIONS is true
if(COMPILER_SUPPORTS_NEON)
    message(STATUS "Compiler supports NEON")
    if(WB_ENABLE_SIMD_OPTIMIZATIONS)
        message(STATUS "WB compile with NEON")
        target_compile_options(wifibroadcast PUBLIC ${WIFIBROADCAST_FEC_OPTIMIZATION_FLAGS_ARM_NEON})
        # I do not know why, but using target_compile_options seems to be not enough ...
        add_compile_options(${WIFIBROADCAST_FEC_OPTIMIZATION_FLAGS_ARM_NEON})
        target_compile_definitions(wifibroadcast PUBLIC WIFIBROADCAST_HAS_ARM_NEON)
    endif()
endif()
if(COMPILER_SUPPORTS_ASIMD)
    message(STATUS "Compiler supports ASIMD")
    if(WB_ENABLE_SIMD_OPTIMIZATIONS)
        message(STATUS "WB compile with ASIMD")
        target_compile_definitions(wifibroadcast PUBLIC WIFIBROADCAST_HAS_ARM_NEON)
    endif ()
endif ()
## FEC Optimizations end ---------------------------------

# We need pcap and libsodium to build wifibroadcast
include(${CMAKE_CURRENT_LIST_DIR}/cmake/FindPCAP.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/FindSodium.cmake)

target_include_directories(wifibroadcast PUBLIC ${sodium_INCLUDE_DIR})
target_include_directories(wifibroadcast PUBLIC ${PCAP_INCLUDE_DIR})
target_link_libraries(wifibroadcast PUBLIC ${PCAP_LIBRARY})
target_link_libraries(wifibroadcast PUBLIC ${sodium_LIBRARY_RELEASE})
target_link_libraries(wifibroadcast PUBLIC ${CMAKE_DL_LIBS})

# for some reason, we also need to manually link pthread
find_package(Threads REQUIRED)
target_link_libraries(wifibroadcast PUBLIC Threads::Threads)
# spdlog might be already exist as a target in OpenHD - only use package manager's spdlog if needed
if(WB_USE_SPDLOG_EXTERNALLY)
    message(STATUS "spdlog needs to be already provided by top cmake")
    # LOL- In openhd we build spdlog into OHDCommonLib and get it from there
    # There were some weird issues with using their cmake and buildroot
    target_link_libraries(wifibroadcast PUBLIC OHDCommonLib)
    target_compile_definitions(wifibroadcast PRIVATE WIFIBROADCAST_OPENHD_LOG_SINK=1)
else ()
    message(STATUS "Using spdlog from package manager")
    if(TARGET spdlog::spdlog)
        target_link_libraries(wifibroadcast PUBLIC spdlog::spdlog)
    else()
        find_package(spdlog QUIET)
        if(spdlog_FOUND)
            target_link_libraries(wifibroadcast PUBLIC spdlog::spdlog)
        else()
            set(WB_OPENHD_SPDLOG_INCLUDE_HINT
                ${CMAKE_CURRENT_LIST_DIR}/../../../../ohd_common/lib/spdlog/include)
            if(EXISTS "${WB_OPENHD_SPDLOG_INCLUDE_HINT}/spdlog/spdlog.h")
                set(SPDLOG_INCLUDE_DIR "${WB_OPENHD_SPDLOG_INCLUDE_HINT}")
            else()
                find_path(SPDLOG_INCLUDE_DIR spdlog/spdlog.h)
            endif()
            if(SPDLOG_INCLUDE_DIR)
                message(WARNING "spdlog CMake package not found, using header-only spdlog from ${SPDLOG_INCLUDE_DIR}")
                target_include_directories(wifibroadcast PUBLIC ${SPDLOG_INCLUDE_DIR})
                target_compile_definitions(wifibroadcast PUBLIC SPDLOG_HEADER_ONLY)
            elseif(TARGET OHDCommonLib)
                message(WARNING "spdlog package not found, falling back to OHDCommonLib")
                target_link_libraries(wifibroadcast PUBLIC OHDCommonLib)
            else()
                option(WB_FETCH_SPDLOG "Fetch spdlog if not found on the system" ON)
                if(WB_FETCH_SPDLOG)
                    message(WARNING "spdlog package not found, fetching spdlog with CMake FetchContent")
                    include(FetchContent)
                    set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
                    set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
                    set(SPDLOG_BUILD_BENCH OFF CACHE BOOL "" FORCE)
                    set(SPDLOG_INSTALL OFF CACHE BOOL "" FORCE)
                    FetchContent_Declare(
                        spdlog
                        GIT_REPOSITORY https://github.com/gabime/spdlog.git
                        GIT_TAG v1.12.0
                    )
                    FetchContent_MakeAvailable(spdlog)
                    if(TARGET spdlog::spdlog_header_only)
                        target_link_libraries(wifibroadcast PUBLIC spdlog::spdlog_header_only)
                    else()
                        target_link_libraries(wifibroadcast PUBLIC spdlog::spdlog)
                    endif()
                else()
                    message(FATAL_ERROR "spdlog package not found. Install spdlog or set spdlog_DIR.")
                endif()
            endif()
        endif()
    endif()
endif ()


SET(WB_TARGET_LINK_LIBRARIES wifibroadcast)
SET(WB_INCLUDE_DIRECTORES ${CMAKE_CURRENT_LIST_DIR}/wifibroadcast)
