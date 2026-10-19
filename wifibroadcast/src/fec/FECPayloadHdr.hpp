#ifndef FEC_PAYLOAD_HDR_HPP
#define FEC_PAYLOAD_HDR_HPP

#include <cstdint>

#include "wb_endian.h"
/**
 * Encoder and Decoder pair for FEC protected block / packet based data
 * streaming. adds sizeof(FECPayloadHdr) to each fec primary or secondary
 * packet.
 */

static_assert(__BYTE_ORDER == __LITTLE_ENDIAN,
              "This code is written for little endian only !");

struct FECPayloadHdr {
  // Most often each frame is encoded as one fec block
  // rolling
  uint32_t block_idx = 0;
  // each fragment inside a block has a fragment index
  // uint8_t is enough, since we are limited to 128+128=256 fragments anyway by
  // the FEC impl.
  uint8_t fragment_idx = 0;
  // how many fragments make up the primary fragments part, the rest is
  // secondary fragments note that we do not need to know how many secondary
  // fragments have been created - as soon as we 'have enough', we can perform
  // the FEC correction step if necessary
  uint8_t n_primary_fragments = 0;
  // For FEC all data fragments have to be the same size. We pad the rest during
  // encoding / decoding with 0, and do this when encoding / decoding such that
  // the 0 bytes don't have to be transmitted. This needs to be included during
  // the fec encode / decode step !
  uint16_t data_size = 0;
} __attribute__((packed));
static_assert(sizeof(FECPayloadHdr) == 8);

#endif  // FEC_PAYLOAD_HDR_HPP