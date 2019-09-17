#include <stdio.h>
int main(int argc, char **argv) {
   int (*p)();
   p = 0x0;
   return printf("%d\n", (*p)());
}