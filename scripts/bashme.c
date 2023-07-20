#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(void)
{
  setresuid(0,0,0);
  system("/bin/bash");
  return 0;
}
