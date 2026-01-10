# How Wifibroadcast Works and Handles Multiple Cards

This document explains the internal working of the `wifibroadcast` library based on the source code, specifically focusing on the `WBTxRx` class.

## Overview

`wifibroadcast` implements a low-latency, connectionless, bidirectional link using Wi-Fi monitor mode and packet injection. It bypasses standard Wi-Fi association and handshakes, allowing for "broadcast" style communication similar to analog video links but with digital data.

## Core Mechanism

The core logic resides in `wifibroadcast/src/WBTxRx.cpp` and `wifibroadcast/src/WBTxRx.h`.

### 1. Initialization
When the `WBTxRx` instance is created:
- It iterates through the provided list of `WifiCard` objects.
- For each card, it initializes packet capture (PCAP) handles:
  - **RX:** Opens the interface in monitor mode using libpcap (`pcap_open_live`) to capture all air traffic.
  - **TX:** Opens the interface for packet injection, either using libpcap (`pcap_inject`) or raw sockets (`socket(AF_PACKET, SOCK_RAW, ...)`), depending on configuration.
- It generates or loads encryption keys (using libsodium).

### 2. Transmission (TX)
Sending data happens in `tx_inject_packet`. The process is as follows:
1.  **Packet Construction:**
    - **Radiotap Header:** Adds a header containing radio information (rate, tx flags).
    - **IEEE 802.11 Header:** Constructs a raw 802.11 Data frame. It sets specific fields (like specific MAC addresses or sequence numbers) to identify the packet as an OpenHD/Wifibroadcast packet.
    - **Payload:** The actual data is appended.
2.  **Encryption:** The payload is authenticated and optionally encrypted using ChaCha20-Poly1305. A unique nonce is generated for each packet.
3.  **Injection:** The constructed packet is injected directly into the air interface.
    - Importantly, transmission happens on **one active card** at a time (`m_curr_tx_card`), even if multiple are available.

### 3. Reception (RX)
Receiving data runs in a dedicated thread (`loop_receive_packets`):
1.  **Polling:** It uses `poll()` to wait for data on the file descriptors of *all* configured cards simultaneously.
2.  **Packet capture:** When data is available, it reads packets via `pcap_next`.
3.  **Filtering & Processing (`on_new_packet`):**
    - **Radiotap Parsing:** Checks for signal quality (RSSI, Noise) and verifies the Frame Check Sequence (FCS).
    - **802.11 Parsing:** Filters for data frames and checks for specific OpenHD headers/IDs to distinguish its own traffic from other Wi-Fi traffic.
    - **Decryption:** Attempts to authenticate/decrypt the packet using the session key.
    - **Deduplication:** The decryption/authentication step (and sequence number tracking) ensures valid data is passed up to the application.

## Handling Multiple Cards

The library is designed to support multiple Wi-Fi cards (MIMO / Diversity) to improve link reliability and range.

### Multiple RX (Diversity)
*   **Simultaneous Listening:** All configured cards listen for packets simultaneously. The `poll()` call monitors all card file descriptors.
*   **Redundancy:** If one card misses a packet due to interference or fading, another card might receive it.
*   **Stats Per Card:** The system tracks statistics (RSSI, Signal Quality, Packet Loss) independently for each card (`m_rx_stats_per_card`). This is useful for identifying bad antennas or hardware issues.
*   **Packet Aggregation:** Valid packets from *any* card are accepted. If multiple cards receive the same packet, the system processes the first valid one it sees.

### Multiple TX (Antenna Switching)
*   **Single Active TX:** Unlike RX, transmission only occurs on **one card** at any given moment. This is defined by `m_curr_tx_card`.
*   **Auto-Switching Logic:**
    - The `switch_tx_card_if_needed()` function runs periodically (default: every 1 second).
    - It analyzes the reception performance of all cards.
    - **Selection Criteria:** It calculates which card has received the most *valid packets* recently (`count_p_valid`).
    - **Switching:** It switches the active TX card to the one performing best (with some hysteresis to prevent rapid oscillating).
    - **Rationale:** The assumption is that the card receiving the best signal from the remote peer is also the best candidate to transmit back to it (channel reciprocity).
