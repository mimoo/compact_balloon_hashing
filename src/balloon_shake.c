#include <balloon_shake.h>
#include <string.h>
#include <stdlib.h>

// Implementation of SHAKE128
// taken from https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/C/Keccak-more-compact.c

// clang-format off
#define FOR(i,n) for(i=0; i<n; ++i)
typedef unsigned char u8;
typedef unsigned long long int u64;
typedef unsigned int ui;
void Keccak(ui r, ui c, const u8 *in, u64 inLen, u8 sfx, u8 *out, u64 outLen);
void FIPS202_SHAKE128(const u8 *in, u64 inLen, u8 *out, u64 outLen) { Keccak(1344, 256, in, inLen, 0x1F, out, outLen); }
int LFSR86540(u8 *R) { (*R)=((*R)<<1)^(((*R)&0x80)?0x71:0); return ((*R)&2)>>1; }
#define ROL(a,o) ((((u64)a)<<o)^(((u64)a)>>(64-o)))
static u64 load64(const u8 *x) { ui i; u64 u=0; FOR(i,8) { u<<=8; u|=x[7-i]; } return u; }
static void store64(u8 *x, u64 u) { ui i; FOR(i,8) { x[i]=u; u>>=8; } }
static void xor64(u8 *x, u64 u) { ui i; FOR(i,8) { x[i]^=u; u>>=8; } }
#define rL(x,y) load64((u8*)s+8*(x+5*y))
#define wL(x,y,l) store64((u8*)s+8*(x+5*y),l)
#define XL(x,y,l) xor64((u8*)s+8*(x+5*y),l)
void KeccakF1600(void *s)
{
    ui r,x,y,i,j,Y; u8 R=0x01; u64 C[5],D;
    for(i=0; i<24; i++) {
        /*θ*/ FOR(x,5) C[x]=rL(x,0)^rL(x,1)^rL(x,2)^rL(x,3)^rL(x,4); FOR(x,5) { D=C[(x+4)%5]^ROL(C[(x+1)%5],1); FOR(y,5) XL(x,y,D); }
        /*ρπ*/ x=1; y=r=0; D=rL(x,y); FOR(j,24) { r+=j+1; Y=(2*x+3*y)%5; x=y; y=Y; C[0]=rL(x,y); wL(x,y,ROL(D,r%64)); D=C[0]; }
        /*χ*/ FOR(y,5) { FOR(x,5) C[x]=rL(x,y); FOR(x,5) wL(x,y,C[x]^((~C[(x+1)%5])&C[(x+2)%5])); }
        /*ι*/ FOR(j,7) if (LFSR86540(&R)) XL(0,0,(u64)1<<((1<<j)-1));
    }
}
void Keccak(ui r, ui c, const u8 *in, u64 inLen, u8 sfx, u8 *out, u64 outLen)
{
    /*initialize*/ u8 s[200]; ui R=r/8; ui i,b=0; FOR(i,200) s[i]=0;
    /*absorb*/ while(inLen>0) { b=(inLen<R)?inLen:R; FOR(i,b) s[i]^=in[i]; in+=b; inLen-=b; if (b==R) { KeccakF1600(s); b=0; } }
    /*pad*/ s[b]^=sfx; if((sfx&0x80)&&(b==(R-1))) KeccakF1600(s); s[R-1]^=0x80; KeccakF1600(s);
    /*squeeze*/ while(outLen>0) { b=(outLen<R)?outLen:R; FOR(i,b) out[i]=s[i]; out+=b; outLen-=b; if(outLen>0) KeccakF1600(s); }
}
// clang-format on

// wrapper around SHAKE128 to get an output of 32-byte
void hash(uint8_t *output, const uint8_t *input, size_t input_length)
{
  FIPS202_SHAKE128(input, (u64)input_length, output, 32);
}

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
                    const uint8_t *input, size_t input_len)
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

  uint64_t n_blocks;
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
  hash(prng, prng_input, prng_input_length);

  //
  // 1. Filling
  //

  // hashed_password = SHA-256(password)
  uint8_t hashed_input[BLOCK_SIZE];
  hash(hashed_input, input, input_len);
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
  hash(buffer, to_hash, total_length);

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
    hash(current_block, to_hash, to_hash_length);
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
        hash(prng, prng, BLOCK_SIZE);
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
      hash(cur_block, to_hash, to_hash_length);
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