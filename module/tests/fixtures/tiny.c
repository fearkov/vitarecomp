/* a module small enough to keep as a test fixture: code that calls an
   import, takes the address of another, and data full of pointers, so that
   the relocations cover the kinds compilers emit. */

int sceKernelDelayThread(unsigned int usec);
int sceKernelExitProcess(int status);

static int counter;
int table[64] = { 1, 2, 3 };
int *pointers[8] = { &counter, &table[1], &table[63], 0 };
int (*delay)(unsigned int) = sceKernelDelayThread;

static int step(int x) { return x * 3 + table[x & 63]; }
int (*steps[4])(int) = { step, step, step, step };

int main(void) {
    for (int i = 0; i < 4; i++)
        counter += steps[i](i) + *pointers[i & 1];
    delay(100);
    sceKernelExitProcess(counter);
    return 0;
}
