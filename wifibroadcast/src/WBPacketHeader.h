#pragma once

#include <cstdint>

// Packet types
#define WB_PACKET_TYPE_VIDEO 0
#define WB_PACKET_TYPE_TELEMETRY 1
#define WB_PACKET_TYPE_RC 2
#define WB_PACKET_TYPE_RETRANSMISSION_REQ 3

// Packet flags
#define WB_PACKET_FLAG_RETRANSMITTED (1 << 0)

// Header structure close to Ruby's implementation but simplified for this task
struct WBPacketHeader {
    uint32_t uCRC;            // CRC for the packet
    uint8_t packet_flags;     // Flags (e.g., retransmitted)
    uint8_t packet_type;      // Type (Video, Telemetry, RC, etc.)
    uint32_t stream_packet_idx; // Sequence number for the stream
    uint16_t total_length;      // Total length of the packet including header
    // Additional fields can be added here to match Ruby's t_packet_header if needed
    // u16 radio_link_packet_index;
    // u32 vehicle_id_src;
    // u32 vehicle_id_dest;
} __attribute__((packed));
