#ifndef AMD64_H
#define AMD64_H

#include "global.h"

typedef enum Regs_x64 {
    RAX, RCX,
    RDX, RBX,
    RSP, RBP,
    RSI, RDI,
    R8,  R9,
    R10, R11,
    R12, R13,
    R14, R15,
    RIP
} Regs_x64;

typedef enum Scale_x64 {
    x1,
    x2,
    x4,
    x8
} Scale_x64;

typedef enum Mode_x64 {
    INDIRECT,
    BYTE_DISPLACED_INDIRECT,
    DISPLACED_INDIRECT,
    DIRECT
} Mode_x64;

void EmitModRm(shellcode_t *code, uint8_t mod, uint8_t rx, uint8_t rm);
void EmitDirect(shellcode_t *code, uint8_t rx, Regs_x64 operand);
void EmitIndirect(shellcode_t *code, uint8_t rx, Regs_x64 base);
void EmitDiplaced(shellcode_t *code, const uint8_t rx, 
    const uint32_t displacement);
void EmitIndirectDisplacedRip(shellcode_t *code, uint8_t rx, 
    uint32_t displacement);
void EmitIndirectByteDisplaced(shellcode_t *code, uint8_t rx, 
    Regs_x64 base, uint8_t displacement);
void EmitIndirectDisplaced(shellcode_t *code, uint8_t rx, 
    Regs_x64 base, uint32_t displacement);
void EmitIndirectIndexed(shellcode_t *code, uint8_t rx, 
    Regs_x64 base, Regs_x64 index, Scale_x64 scale);

void EmitIndirectIndexedByteDisplaced(shellcode_t *code, 
    uint8_t rx, Regs_x64 base, Regs_x64 index, 
    Scale_x64 scale, uint8_t displacement);

void EmitIndirectIndexedDisplaced(shellcode_t *code, 
    uint8_t rx, Regs_x64 base, Regs_x64 index, 
    Scale_x64 scale, uint32_t displacement);


void EmitRexIndexed(shellcode_t *code,  Regs_x64 rx, 
    Regs_x64 base, Regs_x64 index);

void EmitRex(shellcode_t *code,  Regs_x64 rx, Regs_x64 base);

#endif
