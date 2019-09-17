
void function1() {
   int collector = 5, i = 0;
   if (10) {
      for (i=0; i < 100; i++) {
         collector+=i;
      }
   }  else {
      for (i=0; i > 35; i--) {
         collector-=i;
      }
   }
}

int main(int argc, char **argv) {
   void (*functionptr)() = function1;
   functionptr++; // go to an invalid place
   functionptr();
}
