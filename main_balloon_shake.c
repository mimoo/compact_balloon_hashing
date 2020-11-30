#include <balloon_shake.h>
#include <stdlib.h>
#include <stdio.h>

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
                            sizeof(passwd) - 1);

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
