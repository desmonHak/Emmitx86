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
    void (*Emit64)(struct shellcode_t* code, uint64_t bytes);
    void (*expand)(struct shellcode_t* code);
    void (*free  )(struct shellcode_t* code);
    void (*dump  )(const struct shellcode_t *shell);
} shellcode_t;

shellcode_t init_shellcode();




typedef enum ConditionCode {
    O,
    NO,
    B,
    NB,
    E,
    NE,
    NA,
    A,
    S,
    NS,
    P,
    NP,
    L,
    NL,
    NG,
    G,
    NAE = B,
    C = B,
    AE = NB,
    NC = NB,
    Z = E,
    NZ = NE,
    BE = NA,
    NBE = A,
    PE = P,
    PO = NP,
    NGE = L,
    GE = NL,
    LE = NG,
    NLE = G
} ConditionCode;

/**
 * @brief Para los saltos condicionales:
 * 
 */
#define op_cond(operation) Emit_##operation##_C_I
#define OP2CI(operation, opcode) \
void static inline op_cond(operation)(shellcode_t* code, ConditionCode condition_code) { \
    call(code, Emit8, 0x0F); \
    call(code, Emit8, opcode + condition_code); \
}

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

// https://mailund.dk/posts/macro-metaprogramming/
// macro para las instrucciones de longitud de opcode variable las cuales
// no son necesarias de procesar(como cpuid que se puede emitir sin ningun pro-
// cesamiento)
#define op_inm(operation) Emit_##operation##_INM

// macros recursivas para poder aplicar una func a cada arg de una macro dada
// se necesita tabtas de estas macros como args queremos soportar en nuestra 
// macro
#define APPLY_TO_EACH_1(f, x) f(x)
#define APPLY_TO_EACH_2(f, x, ...) f(x) APPLY_TO_EACH_1(f, __VA_ARGS__)
#define APPLY_TO_EACH_3(f, x, ...) f(x) APPLY_TO_EACH_2(f, __VA_ARGS__)
#define APPLY_TO_EACH_4(f, x, ...) f(x) APPLY_TO_EACH_3(f, __VA_ARGS__)
#define APPLY_TO_EACH_5(f, x, ...) f(x) APPLY_TO_EACH_4(f, __VA_ARGS__)

// Esta macro elige la correcta según el número de argumentos
#define GET_MACRO(_1,_2,_3,_4,_5,NAME,...) NAME
// aplicar la funcion a cada argumento segun se indique:
#define APPLY_TO_EACH(f, ...) \
GET_MACRO(__VA_ARGS__, APPLY_TO_EACH_5, APPLY_TO_EACH_4, APPLY_TO_EACH_3, \
    APPLY_TO_EACH_2, APPLY_TO_EACH_1)(f, __VA_ARGS__)

// la funcion a la que aplicaremos a cada arg de nuestra macro
#define procesar(x) call(code, Emit8, x);
#define OP1INM(operation, ...) \
void static inline op_inm(operation)(shellcode_t* code) {  \
    APPLY_TO_EACH(procesar, __VA_ARGS__);                    \
}

// instrucciones:
#define EMIT_INM(ptr_sc, operation) op_inm(operation)(ptr_sc)
OP1INM(CPUID, 0x0F, 0xA2)
OP1INM(CLC, 0xF8)
OP1INM(STC, 0xF9)
OP1INM(CLI, 0xFA)
OP1INM(STI, 0xFB)
OP1INM(CLD, 0xFC)
OP1INM(STD, 0xFD)

OP1INM(INVD,   0x0F, 0x08)
OP1INM(WBINVD, 0x0F, 0x09) // Undefined Instruction
OP1INM(UD2,    0x0F, 0x0B)
OP1INM(NOP,    0x90)
OP1INM(FWAIT,  0x9B)
OP1INM(RETN,   0xC3)
OP1INM(RETF,   0xCB)
OP1INM(UD1,    0xD6)
OP1INM(FDECSTP,0xD9, 0xF6)
OP1INM(FINCSTP,0xD9, 0xF7)

OP1INM(HLT,    0xF4)
OP1INM(CMC,    0xF4)

// SEE2 set
OP1INM(PAUSE,    0xF3, 0x90)

// VMX set
OP1INM(VMCALL,   0x0F, 0x01, 0xC1)
OP1INM(VMLAUNCH, 0x0F, 0x01, 0xC2)
OP1INM(VMRESUME, 0x0F, 0x01, 0xC3)
OP1INM(VMXOFF,   0x0F, 0x01, 0xC4)


OP1R(MOV, 0x8B)
OP1M(MOV, 0x89)

OP1M(ADD, 0x01)
OP1R(ADD, 0x03)
OP1I(ADD, 0x81, 0x00)

OP1M(AND, 0x21)
OP1R(AND, 0x23)
OP1I(AND, 0x81, 0x04)

OP1X(MUL, 0xF7, 0x04)
// EMIT_X_R(MUL, RBX) // mul rbx
// EMIT_X_M(MUL, RBX) // mul [rbx]

// JMP incondicional:
OP1I(JMP, 0xE9, 0x00)

// JCC(Jump-conditions) condicionales
OP2CI(J, 0x80)


// casos mov especiales:
#define EMIT_I(ptr_sc, operation, source_inmmediate) \
    EmitRex(ptr_sc, 0, 0); \
    op_inmed(operation)(ptr_sc); \
    call(ptr_sc, Emit32, source_inmmediate);

#define EMIT_MOV_R_I(ptr_sc, destination, source_inmmediate) \
    EmitRex(ptr_sc, destination, 0); \
    call(ptr_sc, Emit8, 0xB8); \
    call(ptr_sc, Emit64, source_inmmediate);

#define EMIT_MOV_RAX_OFF(ptr_sc, source_offset) \
    EmitRex(ptr_sc, 0, 0); \
    call(ptr_sc, Emit8, 0xA1); \
    call(ptr_sc, Emit64, source_offset);

#define EMIT_MOV_OFF_RAX(ptr_sc, destination_offset) \
    EmitRex(ptr_sc, 0, 0); \
    call(ptr_sc, Emit8, 0xA3); \
    call(ptr_sc, Emit64, destination_offset);

/**
 * @brief Emisor para saltos condicionales
 * 
 */
#define EMIT_C_I(ptr_sc, operation, condition_code, source_immediate) \
    op_cond(operation)(ptr_sc, condition_code); \
    call(ptr_sc, Emit32, source_immediate);

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