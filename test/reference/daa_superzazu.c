#include "i8080.h"
#include <assert.h>
#include <stdio.h>

static uint8_t fetch(void *context, uint16_t address) {
  (void)context;
  (void)address;
  return 0x27;
}

int main(void) {
  for (int a = 0; a < 256; ++a)
    for (int ac = 0; ac < 2; ++ac)
      for (int cy = 0; cy < 2; ++cy) {
        i8080 cpu;
        i8080_init(&cpu);
        cpu.read_byte = fetch;
        cpu.a = a;
        cpu.hf = ac;
        cpu.cf = cy;
        i8080_step(&cpu);
        /* Intel's two stages, retaining the transient carry/full-width value. */
        unsigned low = a;
        if (a % 16 > 9 || ac) low += 6;
        unsigned final = low;
        if (low / 16 > 9 || cy) final += 96;
        assert(cpu.a == final % 256);
        assert(cpu.cf == (cy || final > 255));
        assert(cpu.hf == ((a % 16) + (low - a) > 15));
        /* MAME's original-accumulator predicates and AC bit-4 relation. */
        unsigned correction = (ac || (a & 15) > 9 ? 6 : 0)
                            + (cy || a > 0x99 ? 0x60 : 0);
        assert(cpu.a == ((a + correction) & 255));
        assert(cpu.hf == (((a ^ cpu.a) & 16) != 0));
        assert(cpu.cf == (cy || a > 0x99));
        putchar(cpu.a);
        putchar((cpu.sf << 7) | (cpu.zf << 6) | (cpu.hf << 4)
                | (cpu.pf << 2) | 2 | cpu.cf);
      }
  return 0;
}
