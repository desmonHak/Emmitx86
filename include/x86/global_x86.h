#ifndef EMMIT_GLOBAL_X86_H
#define EMMIT_GLOBAL_X86_H

#include "global_emmit.h"


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

OP1M(XCHG, 0x87)
OP1R(XCHG, 0x87)
//OP1I(XCHG, xxx, xxx)

OP1M(SUB, 0x29)
OP1R(SUB, 0x2B)
OP1I(SUB, 0x81, 0x05)

OP1M(AND, 0x21)
OP1R(AND, 0x23)
OP1I(AND, 0x81, 0x04)

OP1X(MUL, 0xF7, 0x04)
// EMIT_X_R(MUL, RBX) // mul rbx
// EMIT_X_M(MUL, RBX) // mul [rbx]

OP1X(DIV, 0xF7, 0x06)

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
    EmitRex(ptr_sc, 0, destination); \
    call(ptr_sc, Emit8, (0xB8 + (destination & 7))); \
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