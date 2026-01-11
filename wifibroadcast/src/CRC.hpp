#ifndef WIFIBROADCAST_CRC_HPP
#define WIFIBROADCAST_CRC_HPP

#include <cstdint>
#include <cstddef>
#include <array>

namespace wifibroadcast {

// Table-based CRC32 implementation
// Polynomial: 0xEDB88320
static constexpr std::array<uint32_t, 256> generate_crc32_table() {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (uint32_t j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
    return table;
}

static constexpr auto crc32_table = generate_crc32_table();

static uint32_t crc32(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        uint8_t index = (crc ^ data[i]) & 0xFF;
        crc = (crc >> 8) ^ crc32_table[index];
    }
    return ~crc;
}

} // namespace wifibroadcast

#endif // WIFIBROADCAST_CRC_HPP
