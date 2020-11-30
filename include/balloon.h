#ifndef __BALLOON_H__
#define __BALLOON_H__

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#define SALT_LEN (32)
#define BLOCK_SIZE (32)
#define DELTA (5)

// struct containing options
struct balloon_options
{
  // space cost (main buffer size)
  uint32_t s_cost;
  // time cost (number of rounds)
  uint32_t t_cost;
};

typedef void (*callback_sha256)(uint8_t *output, const uint8_t *input, size_t input_length);

// The Balloon key derivation function which assumes that the input might be of low entropy
// ========================================================================================
// - out: the raw output result. It is up to the caller to encode this if needed (in base64 for example)
// - balloon_options: parameters for the algorithm
// - salt: a 32-byte customization argument (a different salt will produce a different output under the same key and options)
// - input: the input password
// - input_len: the input password length
// - callback_sha256: a callback to a SHA-256 implementation
//
// tips
// ====
// - You can optionally call this function in different threads with different salts,
//   and XOR the different results, to increase its strength
// - this needs guidelines on what are good s_cost and t_cost.
int slow_derive_key(uint8_t out[BLOCK_SIZE],
                    struct balloon_options *cfg,
                    uint8_t salt[SALT_LEN],
                    const uint8_t *input,
                    size_t input_length,
                    callback_sha256 sha256);

//
//
//

#endif /* __BALLOON_H__ */