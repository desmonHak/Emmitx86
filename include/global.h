#ifndef EMMIT_GLOBAL_H
#define EMMIT_GLOBAL_H

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/**
 * @brief Assertion macro that allows for code to be executed when the condition is false.
 * 
 */
#define assert_code(condition, code, val, ...)  \
    if (!(condition)) {                         \
        code->err = val;                        \
        __VA_ARGS__                             \
    }
        
/**
 * @brief Enumeration of errors that can occur when using the shellcode.
 * 
 */
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

/** 
 * @brief Macro that calls a method on the shellcode struct.
 *
 */
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

#define op_reg(operation) Emit_##operation##_R
#define OP1R(operation, opcode)                              \
void static inline op_reg(operation)(shellcode_t* code) {    \
    call(code, Emit8, opcode);                               \
}

#define op_mem(operation) Emit_##operation##_M
#define OP1M(operation, opcode)                              \
void static inline op_mem(operation)(shellcode_t* code) {    \
    call(code, Emit8, opcode);                               \
}

#define op_inmed(operation) Emit_##operation##_I
#define OP1I(operation, opcode)                              \
void static inline op_inmed(operation)(shellcode_t* code) {  \
    call(code, Emit8, opcode);                               \
}

OP1M(ADD, 0x01)
OP1R(ADD, 0x03)
OP1I(ADD, 0x81)

/* 
 * EMIT_R_R(ADD, RAX, RCX):             add       rax,             rcx 
 * EMIT_M_R(ADD, RAX, RCX):             add      [rax],            rcx
 * EMIT_R_M(ADD, RAX, RCX):             add       rax,            [rcx]
 * EMIT_M_I(ADD, RAX, 0X12345678):      add      [rax],        0X12345678
 * EMIT_R_I(ADD, RAX, 0X12345678):      add       rax,         0X12345678
 * EMIT_SIB_R(ADD, RAX, x4, RCX, RDX):  add [rax + 4 * rcx],       rdx 
 * EMIT_R_SIB(ADD, RAX, x4, RCX, RDX):  add       rax,       [rcx + 4 * rdx] 
 */

/**
 * @brief EMIT_R_R(ADD, RAX, RCX):             add       rax,             rcx 
 * 
 */
#define EMIT_R_R(code, operation, destionation, source) \
    EmitRex(ptr_sc, destination, source);               \
    op_reg(operation)(ptr_sc);                          \
    EmitDirect(ptr_sc, destination, source);            

#define EMIT_R_M(code, operation, destionation, source) \
    EmitRex(ptr_sc, destination, source);               \
    op_reg(operation)(ptr_sc);                          \
    EmitIndirect(ptr_sc, destination, source);         

#define EMIT_R_MD1(code, operation, destionation, source, displacement) \
    EmitRex(ptr_sc, destination, source);               \
    op_reg(operation)(ptr_sc);                          \
    EmitIndirectByteDisplaced(ptr_sc, destination, source, displacement);      

#define EMIT_R_MD(code, operation, destionation, source, displacement) \
    EmitRex(ptr_sc, destination, source);               \
    op_reg(operation)(ptr_sc);                          \
    EmitIndirectDisplaced(ptr_sc, destination, source, displacement);      

#define EMIT_M_R(code, operation, destionation, source, displacement) \
 EmitRex(ptr_sc, destination, source); \
 op_reg(operation)(ptr_sc); \
 EmitIndirectDisplaced(ptr_sc, destination, source);

#define EMIT_M_I(code, operation, destionation, source) \
 EmitRex(ptr_sc, destination, source); \
 op_reg(operation)(ptr_sc); \
 EmitIndirectDisplacedImm(ptr_sc, destination, source);

#define EMIT_R_I(code, operation, destionation, source) \
 EmitRex(ptr_sc, destination, source); \
 op_reg(operation)(ptr_sc); \
 EmitDirectImm(ptr_sc, destination, source);

#define EMIT_SIB_R(code, operation, destionation, index, source) \
 EmitRex(ptr_sc, destination, source); \
 op_reg(operation)(ptr_sc); \
 EmitIndirectIndexedDisplaced(ptr_sc, destination, index, source);

#define EMIT_R_SIB(code, operation, destionation, index, source) \
 EmitRex(ptr_sc, destination, source); \
 op_reg(operation)(ptr_sc); \
 EmitIndirectIndexedDisplaced(ptr_sc, destination, index, source);

#define EMIT_SIB_M(code, operation, destionation, index, source) \
 EmitRex(ptr_sc, destination, source); \
 op_reg(operation)(ptr_sc); \
 EmitIndirectIndexedDisplaced(ptr_sc, destination, index, source);

#define EMIT_M_SIB(code, operation, destionation, index, source) \
 EmitRex(ptr_sc, destination, source); \
 op_reg(operation)(ptr_sc); \
 EmitIndirectIndexedDisplaced(ptr_sc, destination, index, source);

#define EMIT_SIB_I(code, operation, destionation, index, source) \
 EmitRex(ptr_sc, destination, source); \
 op_reg(operation)(ptr_sc); \
 EmitIndirectIndexedDisplacedImm(ptr_sc, destination, index, source);


    
#endif