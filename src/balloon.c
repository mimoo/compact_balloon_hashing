#include <balloon.h>
#include <string.h>
#include <stdlib.h>

//
// high-level API
//

void u32_to_bytearray(uint8_t *to, uint32_t from)
{
  to[0] = from;
  to[1] = from >> 8;
  to[2] = from >> 16;
  to[3] = from >> 24;
}

void u64_to_bytearray(uint8_t *to, uint64_t from)
{
  to[0] = from;
  to[1] = from >> 8;
  to[2] = from >> 16;
  to[3] = from >> 24;
  to[4] = from >> 32;
  to[5] = from >> 40;
  to[6] = from >> 48;
  to[7] = from >> 56;
}

// The main function
int slow_derive_key(uint8_t out[BLOCK_SIZE], struct balloon_options *cfg, uint8_t salt[SALT_LEN],
                    const uint8_t *input, size_t input_len, callback_sha256 sha256)
{
  // sanity check parameters
  if (!out || !input || !salt)
    return -1;
  // input dangerously small?
  if (input_len < 8)
    return -2;
  // check that cfg is sane
  if (cfg->s_cost < 2 || cfg->t_cost < 2) // TODO: better number
  {
    return -3;
  }

  //
  // 0. Initialize state
  //

  uint64_t counter = 0;
  uint64_t n_blocks = 0;
  const uint32_t bsize = BLOCK_SIZE;
  n_blocks = (cfg->s_cost * 1024) / bsize;
  if (n_blocks % 2 != 0)
    n_blocks++;

  // no need for calloc as the buffer gets filled in the first step of the algorithm
  uint8_t *buffer;
  buffer = malloc(n_blocks * BLOCK_SIZE);
  if (!buffer)
  {
    return -4;
  }

  //
  // initialize PRNG
  //

  // prng_input = _
  uint8_t prng[BLOCK_SIZE];
  size_t prng_input_length = SALT_LEN + sizeof(cfg->s_cost) + sizeof(cfg->t_cost);
  uint8_t prng_input[prng_input_length];
  uint8_t *pointer_to_prng_input = prng_input;
  // prng_input = salt
  memcpy(pointer_to_prng_input, salt, SALT_LEN);
  pointer_to_prng_input += SALT_LEN;
  // prng_input = salt | s_cost
  u32_to_bytearray(pointer_to_prng_input, cfg->s_cost);
  pointer_to_prng_input += sizeof(cfg->s_cost);
  // prng_input = salt | s_cost | t_cost
  u32_to_bytearray(pointer_to_prng_input, cfg->t_cost);
  // prng = hash(salt | s_cost | t_cost)
  sha256(prng, prng_input, prng_input_length);

  //
  // 1. Filling
  //

  // hashed_password = SHA-256(password)
  uint8_t hashed_input[BLOCK_SIZE];
  sha256(hashed_input, input, input_len);
  // to_hash = _
  size_t total_length = sizeof(counter) + SALT_LEN + BLOCK_SIZE + sizeof(cfg->s_cost) + sizeof(cfg->t_cost);
  uint8_t to_hash[total_length];
  uint8_t *pointer_to_hash = to_hash;
  // to_hash = counter
  u64_to_bytearray(pointer_to_hash, counter);
  counter++;
  pointer_to_hash += sizeof(counter);
  // to_hash = counter | salt
  memcpy(pointer_to_hash, salt, SALT_LEN);
  pointer_to_hash += SALT_LEN;
  // to_hash = counter | salt | hashed_password
  memcpy(pointer_to_hash, hashed_input, BLOCK_SIZE);
  pointer_to_hash += BLOCK_SIZE;
  // to_hash = counter | salt | hashed_password | s_cost
  u32_to_bytearray(pointer_to_hash, cfg->s_cost);
  pointer_to_hash += sizeof(cfg->s_cost);
  // to_hash = counter | salt | hashed_password | s_cost | t_cost
  u32_to_bytearray(pointer_to_hash, cfg->t_cost);
  // blocks[0] = hash(counter | salt | hashed_password | s_cost | t_cost)
  sha256(buffer, to_hash, total_length);

  // expand step of the algorithm
  const uint8_t *previous_block = buffer;       // blocks[0]
  uint8_t *current_block = buffer + BLOCK_SIZE; // blocks[1]
  for (size_t i = 1; i < n_blocks; i++)
  {
    // to_hash = counter
    uint8_t to_hash_length = sizeof(counter) + BLOCK_SIZE;
    uint8_t to_hash[to_hash_length];
    u64_to_bytearray(to_hash, counter);
    counter++;
    // to_hash = counter | blocks[i-1]
    memcpy(to_hash + sizeof(counter), previous_block, BLOCK_SIZE);
    // blocks[i] = hash(counter | blocks[i-1])
    sha256(current_block, to_hash, to_hash_length);
    previous_block += BLOCK_SIZE;
    current_block += BLOCK_SIZE;
  }

  //
  // 2. Mixing
  //
  uint8_t *last_block = buffer + (BLOCK_SIZE * (n_blocks - 1)); // blocks[-1]
  for (unsigned int j = 0; j < cfg->t_cost; j++)
  {
    for (unsigned int i = 0; i < n_blocks; i++)
    {
      // to_hash = _
      int to_hash_length = sizeof(counter) + BLOCK_SIZE * DELTA;
      uint8_t to_hash[to_hash_length];
      uint8_t *pointer_to_hash = to_hash;
      // to_hash = counter
      u64_to_bytearray(pointer_to_hash, counter);
      counter++;
      pointer_to_hash += sizeof(counter);
      // to_hash = counter | blocks[i-1] | blocks[i]
      uint8_t *cur_block = buffer + (BLOCK_SIZE * i);
      const uint8_t *prev_block = i ? cur_block - BLOCK_SIZE : last_block;
      memcpy(pointer_to_hash, prev_block, BLOCK_SIZE);
      pointer_to_hash += BLOCK_SIZE;
      memcpy(pointer_to_hash, cur_block, BLOCK_SIZE);
      pointer_to_hash += BLOCK_SIZE;
      // pick random blocks 2, 3, 4
      for (size_t n = 2; n < DELTA; n++)
      {
        // prng = hash(prng)
        sha256(prng, prng, BLOCK_SIZE);
        // neighbor = prng % n_blocks
        uint64_t neighbor = 0;
        neighbor = prng[0];
        neighbor = (neighbor << 8) | prng[1];
        neighbor = (neighbor << 8) | prng[2];
        neighbor = (neighbor << 8) | prng[3];
        neighbor = (neighbor << 8) | prng[4];
        neighbor = (neighbor << 8) | prng[5];
        neighbor = (neighbor << 8) | prng[6];
        neighbor = (neighbor << 8) | prng[7];
        neighbor = neighbor % n_blocks;
        // to_hash = counter | blocks[i-1] | blocks[i] | blocks[random] | blocks[random] | blocks[random]
        memcpy(pointer_to_hash, buffer + (BLOCK_SIZE * neighbor), BLOCK_SIZE);
        pointer_to_hash += BLOCK_SIZE;
      }
      // blocks[i] = hash(counter | blocks[i-1] | blocks[i] | blocks[random] | blocks[random] | blocks[random])
      sha256(cur_block, to_hash, to_hash_length);
    }
  }

  //
  // 3. Extract
  //

  // out = blocks[-1]
  memcpy(out, last_block, BLOCK_SIZE);

  //
  // clean up
  //

  // clean memory (note that we don't clean the input password)
  volatile uint8_t *p = buffer;
  for (int i = 0; i < BLOCK_SIZE * n_blocks; i++)
  {
    p[i] = 0;
  }
  free(buffer);

  //
  return 0;
}
