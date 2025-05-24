#ifndef EMMIT_GLOBAL_AARCH64_H
#define EMMIT_GLOBAL_AARCH64_H

#include "global_emmit.h"

// aarch64-linux-gnu-gcc -static hello.c -o hello-aarch64

static inline void ADD_inmmed(
    shellcode_t* code,
    bool sf, bool sh, uint16_t innmed16, 
    uint8_t Rn, uint8_t Rd){
    OPGENERATE(0x11, 0x00, sh << (6 + innmed16) | (innmed16 & 0b111111), (sf << 7) + 0x11);
}

#endif