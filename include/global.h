#ifndef EMMIT_GLOBAL_H
#define EMMIT_GLOBAL_H

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define assert_code(condition, code, val, ...)  \
    if (!(condition)) {                         \
        code->err = val;                        \
        __VA_ARGS__                             \
    }
        

typedef enum err_shellcode {
    NO_ERROR_SC,
    REALLOC_ERROR,
    EmitIndirect_ERROR,
    EmitIndirectByteDisplaced_ERROR,
    EmitIndirectDisplaced_ERROR,
    EmitIndirectIndexed_ERROR,
    EmitIndirectIndexedDisplaced_ERROR,
    EmitIndirectIndexedByteDisplaced_ERROR
} err_shellcode;

// a.free(a)
#define call(this, method, ...) (this)->method((this), ##__VA_ARGS__)

typedef struct shellcode_t {
    size_t        capacity;
    size_t        size;

    uint8_t      *code;
    err_shellcode err;

    void (*Emit8 )(struct shellcode_t* code, uint8_t  byte);
    void (*Emit32)(struct shellcode_t* code, uint32_t bytes);
    void (*expand)(struct shellcode_t* code);
    void (*free  )(struct shellcode_t* code);
    void (*dump  )(const struct shellcode_t *shell);
} shellcode_t;

shellcode_t init_shellcode();

#define OP1R(operation, opcode)                     \
    void Emit_##operation##_R(shellcode_t* code) {  \
        call(code, Emit8, opcode);                  \
    }

#define OP1M(operation, opcode)                     \
    void Emit_##operation##_M(shellcode_t* code) {  \
        call(code, Emit8, opcode);                  \
    }

#define EmitADD_R(ptr_sc) call(ptr_sc, Emit8, 0x03);  
#define EmitADD_M(ptr_sc) call(ptr_sc, Emit8, 0x01);   
#define EmitADD_I(ptr_sc) call(ptr_sc, Emit8, 0x81);   

#endif