#include <balloon.h>
#include <stdlib.h>
#include <stdio.h>

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
void callback_hash(uint8_t *output, const uint8_t *input, size_t input_length)
{
  FIPS202_SHAKE128(input, (u64)input_length, output, 32);
}

//
int main()
{
  // salt
  uint8_t salt[SALT_LEN];
  for (int i = 0; i < SALT_LEN; i++)
  {
    salt[i] = i;
  }

  // options
  struct balloon_options opt = {
      .s_cost = 50, // buffer will be s_cost * 32 bytes
      .t_cost = 4,  // number of rounds
  };

  // password
  uint8_t passwd[] = "abcdefgfioewjfoiwejfiowefjewoifjewiofjweiofjqewoifjqeoifjqofijeqiofh";

  // derive key
  uint8_t out[32];
  int ret = slow_derive_key(out,
                            &opt,
                            salt,
                            passwd,
                            sizeof(passwd) - 1,
                            callback_hash);

  // parse result
  if (ret == 0)
  {
    printf("output: ");
    for (int i = 0; i < 32; i++)
    {
      printf("%02x", out[i]);
    }
    printf("\n");
  }
  else
  {
    printf("error: %d\n", ret);
  }

  //
  return 0;
}
