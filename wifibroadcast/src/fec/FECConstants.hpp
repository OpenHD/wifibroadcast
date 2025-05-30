#ifndef FEC_CONSTANTS_HPP
#define FEC_CONSTANTS_HPP

#include "FECPayloadHdr.hpp"

static constexpr auto FRAGMENT_STATUS_UNAVAILABLE = false;
static constexpr auto FRAGMENT_STATUS_AVAILABLE = true;

// See WBTxRx
static constexpr const auto MAX_PAYLOAD_BEFORE_FEC = 8100;
// The FEC stream encode adds an overhead, leaving X bytes to the application
static constexpr const auto FEC_PACKET_MAX_PAYLOAD_SIZE =
    MAX_PAYLOAD_BEFORE_FEC - sizeof(FECPayloadHdr);
//static_assert(FEC_PACKET_MAX_PAYLOAD_SIZE == 1441);

// max 255 primary and secondary fragments together for now. Theoretically, this
// implementation has enough bytes in the header for up to 15 bit fragment
// indices, 2^15=32768 Note: currently limited by the fec c implementation
static constexpr const uint16_t MAX_N_P_FRAGMENTS_PER_BLOCK = 128;
static constexpr const uint16_t MAX_N_S_FRAGMENTS_PER_BLOCK = 128;
static constexpr const uint16_t MAX_TOTAL_FRAGMENTS_PER_BLOCK =
    MAX_N_P_FRAGMENTS_PER_BLOCK + MAX_N_S_FRAGMENTS_PER_BLOCK;

#endif  // FEC_CONSTANTS_HPP
