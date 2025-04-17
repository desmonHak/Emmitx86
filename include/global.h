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

#define extension(operation) extension_##operation##_I
#define op_inmed(operation) Emit_##operation##_I
#define OP1I(operation, opcode, extension_val)                   \
void static inline op_inmed(operation)(shellcode_t* code) {  \
    call(code, Emit8, opcode);                               \
}                                                            \
enum { extension(operation) = extension_val};

#define op_x(operation) Emit_##operation##_X
#define OP1X(operation, opcode, extension_val)                   \
void static inline op_x(operation)(shellcode_t* code) {  \
    call(code, Emit8, opcode);                               \
}                                                            \
enum { extension_##operation##_X = extension_val};

// instrucciones:

OP1M(ADD, 0x01)
OP1R(ADD, 0x03)
OP1I(ADD, 0x81, 0x00)

OP1M(AND, 0x21)
OP1R(AND, 0x23)
OP1I(AND, 0x81, 0x04)

OP1X(MUL, 0xF7, 0x04)
// EMIT_X_R(MUL, RBX) // mul rbx
// EMIT_X_M(MUL, RBX) // mul [rbx]

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
#define EMIT_R_R(ptr_sc, operation, destination, source) \
    EmitRex(ptr_sc, destination, source);               \
    op_reg(operation)(ptr_sc);                          \
    EmitDirect(ptr_sc, destination, source);            

#define EMIT_R_D(ptr_sc, operation, destination, source_displacement) \
    EmitRex(ptr_sc, destination, 0);               \
    op_reg(operation)(ptr_sc);                          \
    EmitDiplaced(ptr_sc, destination, source_displacement);            

#define EMIT_R_M(ptr_sc, operation, destination, source) \
    EmitRex(ptr_sc, destination, source);               \
    op_reg(operation)(ptr_sc);                          \
    EmitIndirect(ptr_sc, destination, source);         

#define EMIT_R_RIPD(ptr_sc, operation, destination, source_rip_displacement) \
    EmitRex(ptr_sc, destination, 0);                              \
    op_reg(operation)(ptr_sc);                                    \
    EmitIndirectDisplacedRip(ptr_sc, destination, source_rip_displacement);     

#define EMIT_R_MD1(ptr_sc, operation, destination, source, source_displacement) \
    EmitRex(ptr_sc, destination, source);               \
    op_reg(operation)(ptr_sc);                          \
    EmitIndirectByteDisplaced(ptr_sc, destination, source, source_displacement);      

#define EMIT_R_MD(ptr_sc, operation, destination, source, source_displacement) \
    EmitRex(ptr_sc, destination, source);               \
    op_reg(operation)(ptr_sc);                          \
    EmitIndirectDisplaced(ptr_sc, destination, source, source_displacement);      

#define EMIT_R_SIB(ptr_sc, operation, destination, source_base, source_scale, \
    source_index) \
    EmitRexIndexed(ptr_sc, destination, source_base, source_index); \
    op_reg(operation)(ptr_sc); \
    EmitIndirectIndexed(ptr_sc, destination, source_base, \
        source_index, source_scale);

#define EMIT_R_SIBD1(ptr_sc, operation, destination, source_base, source_scale, \
        source_index, source_displacement) \
    EmitRexIndexed(ptr_sc, destination, source_base, source_index); \
    op_reg(operation)(ptr_sc); \
    EmitIndirectIndexedByteDisplaced(ptr_sc, destination, source_base, \
        source_index, source_scale, source_displacement);

#define EMIT_R_SIBD(ptr_sc, operation, destination, source_base, source_scale, \
        source_index, source_displacement) \
    EmitRexIndexed(ptr_sc, destination, source_base, source_index); \
    op_reg(operation)(ptr_sc); \
    EmitIndirectIndexedDisplaced(ptr_sc, destination, source_base, \
        source_index, source_scale, source_displacement);


#define EMIT_RIPD_R(ptr_sc, operation, destination_rip_displacement, source) \
    EmitRex(ptr_sc, source, 0);                              \
    op_mem(operation)(ptr_sc);                                    \
    EmitIndirectDisplacedRip(ptr_sc, source, destination_rip_displacement);  

#define EMIT_D_R(ptr_sc, operation, destination_displacement, source) \
    EmitRex(ptr_sc, source, 0);               \
    op_mem(operation)(ptr_sc);                          \
    EmitDiplaced(ptr_sc, source, destination_displacement);    

#define EMIT_M_R(ptr_sc, operation, destination, source)  \
    EmitRex(ptr_sc, source, destination);               \
    op_mem(operation)(ptr_sc);                          \
    EmitIndirect(ptr_sc, source, destination);         

#define EMIT_MD1_R(ptr_sc, operation, destination, destination_displacement, source) \
    EmitRex(ptr_sc, source, destination);               \
    op_mem(operation)(ptr_sc);                          \
    EmitIndirectByteDisplaced(ptr_sc, source, destination, destination_displacement);  

#define EMIT_MD_R(ptr_sc, operation, destination, destination_displacement, source) \
    EmitRex(ptr_sc, source, destination);               \
    op_mem(operation)(ptr_sc);                          \
    EmitIndirectDisplaced(ptr_sc, source, destination, destination_displacement);     

#define EMIT_SIB_R(ptr_sc, operation, destination_base, destination_scale, \
    destination_index, source)  \
    EmitRex(ptr_sc, destination_base, destination_index);               \
    op_mem(operation)(ptr_sc);                          \
    EmitIndirectIndexed(ptr_sc, source, destination_base, destination_index, \
        destination_scale);   

#define EMIT_SIBD1_R(ptr_sc, operation, destination_base, destination_scale, \
    destination_index, destination_displacement, source)  \
    EmitRex(ptr_sc, destination_base, destination_index);               \
    op_mem(operation)(ptr_sc);                          \
    EmitIndirectIndexedByteDisplaced(ptr_sc, source, destination_base, destination_index, \
        destination_scale, destination_displacement);   

#define EMIT_SIBD_R(ptr_sc, operation, destination_base, destination_scale, \
    destination_index, destination_displacement, source)  \
    EmitRex(ptr_sc, destination_base, destination_index);               \
    op_mem(operation)(ptr_sc);                          \
    EmitIndirectIndexedDisplaced(ptr_sc, source, destination_base, destination_index, \
        destination_scale, destination_displacement);   

#define EMIT_R_I(ptr_sc, operation, destination, source_inmmediate) \
    EmitRex(ptr_sc, 0, destination); \
    op_inmed(operation)(ptr_sc);     \
    EmitDirect(ptr_sc, extension(operation), destination); \
    call(ptr_sc, Emit32, source_inmmediate);

#define EMIT_M_I(ptr_sc, operation, destination, source_inmmediate) \
    EmitRex(ptr_sc, 0, destination); \
    op_inmed(operation)(ptr_sc);     \
    EmitIndirect(ptr_sc, extension(operation), destination); \
    call(ptr_sc, Emit32, source_inmmediate);

#define EMIT_MD1_I(ptr_sc, operation, destination, destination_displacement, \
    source_inmmediate) EmitRex(ptr_sc, 0, destination); \
    op_inmed(operation)(ptr_sc);     \
    EmitIndirectDisplaced(ptr_sc, extension(operation), destination, \
    destination_displacement); \
    call(ptr_sc, Emit32, source_inmmediate);

#define EMIT_MD_I(ptr_sc, operation, destination, destination_displacement, \
    source_inmmediate) EmitRex(ptr_sc, 0, destination); \
    op_inmed(operation)(ptr_sc);     \
    EmitIndirectByteDisplaced(ptr_sc, extension(operation), destination, \
    destination_displacement); \
    call(ptr_sc, Emit32, source_inmmediate);

#define EMIT_SIB_I(ptr_sc, operation, destination_base, destination_scale, \
    destination_index, source_inmmediate) \
    EmitRexIndexed(ptr_sc, 0, destination_base, destination_index); \
    op_inmed(operation)(ptr_sc);     \
    EmitIndirectIndexed(ptr_sc, extension(operation), destination_base, \
        destination_index, destination_scale); \
    call(ptr_sc, Emit32, source_inmmediate);

#define EMIT_SIBD1_I(ptr_sc, operation, destination_base, destination_scale, \
    destination_index, destination_displacement, source_inmmediate) \
    EmitRexIndexed(ptr_sc, 0, destination_base, destination_index); \
    op_inmed(operation)(ptr_sc);     \
    EmitIndirectIndexedByteDisplaced(ptr_sc, extension(operation), destination_base, \
        destination_index, destination_scale, destination_displacement); \
    call(ptr_sc, Emit32, source_inmmediate);

#define EMIT_SIBD_I(ptr_sc, operation, destination_base, destination_scale, \
    destination_index, destination_displacement, source_inmmediate) \
    EmitRexIndexed(ptr_sc, 0, destination_base, destination_index); \
    op_inmed(operation)(ptr_sc);     \
    EmitIndirectIndexedDisplaced(ptr_sc, extension(operation), destination_base, \
        destination_index, destination_scale, destination_displacement); \
    call(ptr_sc, Emit32, source_inmmediate);

#define EMIT_D_I(ptr_sc, operation, destination_displacement, source_inmmediate) \
    EmitRex(ptr_sc, 0, 0);               \
    op_inmed(operation)(ptr_sc);                          \
    EmitDiplaced(ptr_sc, extension(operation), destination_displacement); \
    call(ptr_sc, Emit32, source_inmmediate);

#define EMIT_RIPD_I(ptr_sc, operation, destination_displacement, source_inmmediate) \
    EmitRex(ptr_sc, 0, 0);               \
    op_inmed(operation)(ptr_sc);                          \
    EmitIndirectDisplacedRip(ptr_sc, extension(operation), \
    destination_displacement); \
    call(ptr_sc, Emit32, source_inmmediate);


#define EMIT_X_R(ptr_sc, operation, source) \
    EmitRex(ptr_sc, 0, source);               \
    op_x(operation)(ptr_sc);                \
    EmitDirect(ptr_sc, extension_##operation##_X, source);

#define EMIT_X_RIPD(ptr_sc, operation, source_displacement) \
    EmitRex(ptr_sc, 0, 0);               \
    op_x(operation)(ptr_sc);                          \
    EmitIndirectDisplacedRip(ptr_sc, extension_##operation##_X, \
        source_displacement); 

#define EMIT_X_D(ptr_sc, operation, source_displacement) \
    EmitRex(ptr_sc, 0, 0);               \
    op_x(operation)(ptr_sc);                          \
    EmitDiplaced(ptr_sc, extension_##operation##_X, source_displacement);

#define EMIT_X_M(ptr_sc, operation, source) \
    EmitRex(ptr_sc, 0, source); \
    op_x(operation)(ptr_sc);     \
    EmitIndirect(ptr_sc, extension_##operation##_X, source); 

#define EMIT_X_MD(ptr_sc, operation, source, source_displacement) \
    EmitRex(ptr_sc, 0, source); \
    op_x(operation)(ptr_sc);     \
    EmitIndirectDisplaced(ptr_sc, extension_##operation##_X, source, \
        source_displacement); 

#define EMIT_X_MD1(ptr_sc, operation, source, source_displacement) \
    EmitRex(ptr_sc, 0, source); \
    op_x(operation)(ptr_sc);     \
    EmitIndirectByteDisplaced(ptr_sc, extension_##operation##_X, source, \
    source_displacement); 

#define EMIT_X_SIB(ptr_sc, operation, source_base, source_scale, \
    source_index) \
    EmitRexIndexed(ptr_sc, 0, source_base, source_index); \
    op_x(operation)(ptr_sc);     \
    EmitIndirectIndexed(ptr_sc, extension_##operation##_X, source_base, \
        source_index, source_scale);

#define EMIT_X_SIBD1(ptr_sc, operation, source_base, source_scale, \
    source_index, source_displacement) \
    EmitRexIndexed(ptr_sc, 0, source_base, source_index); \
    op_x(operation)(ptr_sc);     \
    EmitIndirectIndexedByteDisplaced(ptr_sc, extension_##operation##_X, source_base, \
        source_index, source_scale, source_displacement);


#define EMIT_X_SIBD(ptr_sc, operation, source_base, source_scale, \
    source_index, source_displacement) \
    EmitRexIndexed(ptr_sc, 0, source_base, source_index); \
    op_x(operation)(ptr_sc);     \
    EmitIndirectIndexedDisplaced(ptr_sc, extension_##operation##_X, source_base, \
        source_index, source_scale, source_displacement);

#endif