#ifndef EMMIT_GLOBAL_AARCH64_H
#define EMMIT_GLOBAL_AARCH64_H

#include "global_emmit.h"

// https://developer.arm.com/documentation/ddi0602/2025-03/Base-Instructions/ABS--Absolute-value-?lang=en

/**
 * @brief Registers
 * 
 */
typedef enum Regs_arm {
    R0,  R1, 
    R2,  R3, 
    R4,  R5, 
    R6,  R7, 
    R8,  R9, 
    R10, R11, 
    R12, R13, 
    R14, R15, 
    R16, R17, 
    R18, R19, 
    R20, R21, 
    R22, R23, 
    R24, R25, 
    R26, R27, 
    R28, R29, 
    R30, SP
} Regs_x64;

/**
 * Formato binario de ADD (immediate) (donde se usan op y S)
 * 
 * sf | op | S | 1 0 0 0 1 0 | sh | imm12 | Rn | Rd
 * 
 * | Bits  | Campo    | Significado                                                                |
 * | ----- | -------- | -------------------------------------------------------------------------- |
 * | 31    | `sf`     | Tamaño: `0` = 32-bit, `1` = 64-bit                                         |
 * | 30    | `op`     | Operación: `0` = ADD, `1` = SUB                                            |
 * | 29    | `S`      | Set flags: `0` = no afecta NZCV, `1` = afecta (para instrucciones con 'S') |
 * | 28-24 | `100010` | Opcode base para ADD/SUB (inmediato)                                       |
 * | 23    | `sh`     | Shift inmediato (0 = no shift, 1 = LSL #12)                                |
 * | 22-10 | `imm12`  | Inmediato de 12 bits (cero en el caso de MOV alias)                        |
 * | 9-5   | `Rn`     | Registro fuente                                                            |
 * | 4-0   | `Rd`     | Registro destino                                                           |
 * 
 * ¿Qué son op y S?
 * op (bit 30):
 *      0 → operación es ADD
 *      1 → operación es SUB
 * En el caso de MOV como alias de ADD, este bit es 0.
 * S (bit 29):
 *      0 → no actualiza los flags NZCV
 *      1 → sí actualiza flags (se usa en instrucciones como ADDS o SUBS)
 * 
 * En el caso de MOV (o ADD sin afectación de flags), este bit también es 0.
 * 
 * Instrucciones sin "S" (ADD, SUB, etc.)
 *      No afectan los flags del registro de estado del procesador (NZCV).
 *      
 *      Se usan cuando solo te interesa el resultado aritmético, no hacer 
 *      decisiones condicionales basadas en el resultado.
 * 
 * Instrucciones con "S" (ADDS, SUBS, etc.)
 *      Sí actualizan los flags NZCV (Negative, Zero, Carry, Overflow).
 *      
 *      Se usan cuando vas a hacer una comparación o tomar decisiones según el 
 *      resultado (por ejemplo con instrucciones condicionales como B.EQ, 
 *      B.NE, etc).
 * 
 *      N: negativo (si el resultado es negativo)
 *      Z: cero (si el resultado es 0)
 *      C: acarreo (si hubo acarreo fuera del bit más significativo)
 *      V: overflow (si hubo desbordamiento de signo)
 * 
 * MOVZ, MOVN, MOVK tienen el mismo formato básico de instrucción, cambia solo el opcode
 */
#define ENCODE_MOV_WIDE(sf, opc, hw, imm16, Rd) (          \
    ((uint32_t)(sf)    << 31)        |                      \
    ((uint32_t)(opc)   << 23)        |                      \
    ((uint32_t)(hw)    << 21)        |                      \
    ((uint32_t)(imm16) << 5)         |                      \
    ((uint32_t)(Rd)    & 0x1F)                               \
)

/*
 * Se define 5bits pasalos registros en Aarch64
 */
#define MASK_REG 0x1F

#define UInt(val, mask) (val & mask)

// aarch64-linux-gnu-gcc -static hello.c -o hello-aarch64

static inline void ADD_SUB_inmmed(
    shellcode_t* code, bool is_sub, bool sf, bool sh, 
    uint16_t imm12, uint8_t Rn, uint8_t Rd) {
    uint32_t instr = 0;
    instr |= (sf & 1) << 31;          // sf
    instr |= is_sub << 30;                 // op = 1 (SUB)
    instr |= 0 << 29;                 // S = 0 (no flags)
    instr |= 0b100010 << 23;          // base opcode bits [28:23]
    instr |= (sh & 1) << 22;          // sh (shift)
    instr |= (imm12 & 0xFFF) << 10;   // imm12
    instr |= (Rn & 0x1F) << 5;        // Rn
    instr |= (Rd & 0x1F);             // Rd

    code->Emit32(code, instr);
}



static inline void ADD_SUB_S(shellcode_t* code, bool is_sub, bool sf, bool sh, uint16_t imm12, uint8_t Rn, uint8_t Rd) {
    uint32_t instr = 0;
    instr |= (sf & 1) << 31;
    instr |= (is_sub ? 1 : 0) << 30;  // op
    instr |= 1 << 29;                // S = 1
    instr |= 0b100010 << 23;
    instr |= (sh & 1) << 22;
    instr |= (imm12 & 0xFFF) << 10;
    instr |= (Rn & 0x1F) << 5;
    instr |= (Rd & 0x1F);

    code->Emit32(code, instr);
}
// CMP (alias de SUBS Rd=XZR)
#define CMP(code, sf, Rn, imm12) ADD_SUB_S(code, 1, sf, 0, imm12, Rn, 31)

static inline void LOGIC_REG(shellcode_t* code, uint8_t opcode, bool sf, uint8_t Rn, uint8_t Rm, uint8_t Rd) {
    uint32_t instr = 0;
    instr |= (sf & 1) << 31;
    instr |= (opcode & 0x7) << 29;   // AND=0b000, ORR=0b001, EOR=0b010
    instr |= 0b01010 << 24;          // base
    instr |= (Rm & 0x1F) << 16;
    instr |= 0 << 10;                // shift amount
    instr |= (Rn & 0x1F) << 5;
    instr |= (Rd & 0x1F);
    code->Emit32(code, instr);
}
#define AND(code, sf, Rn, Rm, Rd) LOGIC_REG(code, 0b000, sf, Rn, Rm, Rd)
#define ORR(code, sf, Rn, Rm, Rd) LOGIC_REG(code, 0b001, sf, Rn, Rm, Rd)
#define EOR(code, sf, Rn, Rm, Rd) LOGIC_REG(code, 0b010, sf, Rn, Rm, Rd)

static inline void EmitBitfield(
    shellcode_t* code, bool sf, bool is_signed, bool N_field,
    uint8_t Rn, uint8_t Rd, uint8_t immr, uint8_t imms
    ) {
    uint32_t instr = 0;

    instr |= ((uint32_t)(sf & 1)) << 31;           // sf: 0 = 32-bit, 1 = 64-bit
    uint8_t opc = is_signed ? 0b00 : 0b10;         // opc field 
    instr |= ((uint32_t)(opc & 0b11)) << 29;       // UBFM = 0b10
    instr |= 0b100110 << 23;                       // base opcode
    instr |= N_field << 22;                        // Campo N
    instr |= ((uint32_t)(immr & 0x3F)) << 16;
    instr |= ((uint32_t)(imms & 0x3F)) << 10;
    instr |= ((uint32_t)(Rn & 0x1F)) << 5;
    instr |= ((uint32_t)(Rd & 0x1F));

    code->Emit32(code, instr);
}

/**
 * @brief Las instrucciones LSL, LSR y ASR tienen un campo (N = 1) == SF
 * si es para 64bits, y tendran este campo a 0 cuando LSL, LSR o ASR
 * tengan el campo (SF = 0) == (N = 0)
 */
#define LSL_inmmed(code, sf, Rn, Rd, shift)                    \
        EmitBitfield(                                   \
            code, sf, false, sf, Rn, Rd,                \
            (sf ? (64 - (shift)) : (32 - (shift))),     \
            (sf ? (63 - (shift)) : (31 - (shift))));

#define LSR_inmmed(code, sf, Rn, Rd, shift) \
    EmitBitfield(code, sf, false, sf, Rn, Rd, shift, (sf ? 63 : 31))

#define ASR_inmmed(code, sf, Rn, Rd, shift) \
    EmitBitfield(code, sf, true, sf, Rn, Rd, shift, (sf ? 63 : 31))


// Branch y condicionales
// B, BL, RET, BR
#define B(code, imm26)  \
    uint32_t instr = 0x14000000 | ((imm26) & 0x03FFFFFF); \
    code->Emit32(code, instr); \

#define BL(code, imm26) \
    uint32_t instr = 0x94000000 | ((imm26) & 0x03FFFFFF); \
    code->Emit32(code, instr); \

#define RET(code) code->Emit32(code, 0xD65F03C0)     // RET LR

#define BR(code, Rn)\
    uint32_t instr = 0xD61F0000 | ((Rn & 0x1F) << 5); \
    code->Emit32(code, instr); \

    #define B_COND(code, cond, imm19) do { \
    uint32_t instr = 0x54000000 | (((imm19) & 0x7FFFF) << 5) | ((cond) & 0xF); \
    code->Emit32(code, instr); \
} while (0)

// Saltos condicionales (B.cond)
#define B_EQ(code, imm19) B_COND(code, 0x0, imm19)
#define B_NE(code, imm19) B_COND(code, 0x1, imm19)
#define B_LT(code, imm19) B_COND(code, 0xB, imm19)
#define B_GE(code, imm19) B_COND(code, 0xA, imm19)
#define B_HI(code, imm19) B_COND(code, 0x8, imm19)
#define B_LO(code, imm19) B_COND(code, 0x3, imm19)


/**
 * @brief Carga y Almacenamiento (LDR, STR)
 * Formato base: 64-bit, offset inmediato
 * 
 * 
 * Bits [31:30] size: size = 1 == 32bits size = 0 == 32bits
 * Bit 22: opc (0 = store, 1 = load)
 * Bits [28:27]: 111 → Load/store unsigned immediate
 * Bits [21:10]: imm12 (offset inmediato escalado, 
 *      el valor real es imm12 * size_in_bytes)
 * Bits [9:5]: Rn (base register)
 * Bits [4:0]: Rt (target register)
 */
#define ENCODE_LDST(is_load, size, imm9, post_pre_index, Rn, Rt) ( \
    ((uint32_t)(size | 0x2) << 30)           | /* bits 31:30. el bit 31 siempre es 1 al parecer */ \
    (0b111 << 27)                            | /* bits 29:27 = 111 (load/store unsigned immediate) */ \
    ((uint32_t)(is_load) << 22)              | /* bit 22: 1=load, 0=store */ \
    ((uint32_t)(imm9 & 0xFFF) << 12)         | /* bits 21:12 */ \
    ((uint32_t)(post_pre_index & 0x1F) << 10)| /* bits 11:10 */ \
    ((uint32_t)(Rn & 0x1F) << 5)             | /* bits 9:5 */ \
    ((uint32_t)(Rt & 0x1F)))                   /* bits 4:0 */

// Más alias de lógica usando tu función LOGIC_REG
#define ANDS(code, sf, Rn, Rm, Rd) { \
    uint32_t instr = 0; \
    instr |= (sf & 1) << 31; \
    instr |= (0b100) << 29; /* opcode ANDS */ \
    instr |= 0b01010 << 24; \
    instr |= (Rm & 0x1F) << 16; \
    instr |= 0 << 10; /* shift */ \
    instr |= (Rn & 0x1F) << 5; \
    instr |= (Rd & 0x1F); \
    code->Emit32(code, instr); \
}

#define LDR_POST_inmmed(code, size, imm9, Rn, Rt) \
    code->Emit32(code, ENCODE_LDST(1, size, imm9, 0, Rn, Rt))
#define LDR_PRE_inmmed(code, size, imm9, Rn, Rt) \
    code->Emit32(code, ENCODE_LDST(1, size, imm9, 1, Rn, Rt))

// tiene version post y pre index la version inmmed?
#define STR_POST(code, size, imm9, Rn, Rt) \
    code->Emit32(code, ENCODE_LDST(0, size, imm9, 0, Rn, Rt))
#define STR_PRE(code, size, imm9, Rn, Rt) \
    code->Emit32(code, ENCODE_LDST(0, size, imm9, 1, Rn, Rt))

/**
 * @brief CBZ / CBNZ
 * if (Rt == 0) PC = PC + offset;   // Salta a label
 * else PC = PC + 4;                // Continúa a la siguiente instrucción
 */
#define CBZ(code, sf, Rt, imm19)        \
    code->Emit32(                       \
        code,                           \
        0x34000000                  |   \
        ((sf & 1) << 31)            |   \
        (((imm19) & 0x7FFFF) << 5)  |   \
        (Rt & 0x1F));

/**
 * @brief CBZ / CBNZ
 * if (Rt == 0) PC = PC + offset;   // Salta a label
 * else PC = PC + 4;                // Continúa a la siguiente instrucción
 */
#define CBNZ(code, sf, Rt, imm19) \
    code->Emit32(code, 0x35000000 | ((sf & 1) << 31) | (((imm19) & 0x7FFFF) << 5) | (Rt & 0x1F));

// algunos alias:
#define NOP(code) code->Emit32(code, 0xD503201F)
#define CLR(code, Rd) MOV_REG(code, 1, 31, Rd)
// NEG Rd, Rn: Resta Rn de 0 para obtener el negativo (-Rn)
// Se usa SUB con XZR como minuendo
#define NEG(code, sf, Rn, Rd) SUB_inmmed(code, true, sf, 0, 0, Rn, Rd)  // con XZR
//#define NOT(code, sf, Rn, Rd) ORR(code, sf, 31, Rn, Rd)

// Alias para instrucciones MOV con valores especiales
// CLR Rd: limpia el registro (mov Rd, XZR)
#define CLR(code, Rd) MOV_REG(code, 1, 31, Rd)  // ORR Rd, XZR, XZR == 0
#define CALL(code, imm26) BL(code, imm26)



// NOT Rd, Rn: Negación bit a bit (invirtiendo bits)
// NOT es ORR Rd, Rn, ~Rn (no existe directo, usamos MVN o equivalente)
// En AArch64, NOT es EOR con todos bits a 1 (XZR con complemento)
#define NOT(code, sf, Rn, Rd) EOR(code, sf, Rn, 31, Rd) // EOR Rd, Rn, XZR (XZR actúa como 0), pero para NOT hay que usar MVN o mov invertido, aquí lo dejamos como alias simple


/**
 * MOV Rd, Rn (sin SP) → ORR Rd, Rn, Rn
 * Usa la instrucción ORR Rd, Rn, Rn para representar MOV
 */
static inline void MOV_REG(
    shellcode_t* code,
    bool sf,
    uint8_t Rn,
    uint8_t Rd)
{
    // Codifica: ORR Rd, Rn, Rn
    uint32_t instr = 0;
    instr |= (sf & 0x1) << 31;         // sf
    instr |= 0b0101010 << 24;         // opcode for ORR (shifted register)
    instr |= 0 << 22;                  // shift = LSL
    instr |= 0 << 21;                  // N = 0
    instr |= 0 << 16;                  // imm6 = 0
    instr |= (Rn & 0x1F) << 5;         // Rn
    instr |= (Rn & 0x1F) << 16;        // Rm = Rn
    instr |= (Rd & 0x1F);              // Rd
    printf("MOV_REG (ORR): 0x%08X\n", instr);
    (code)->Emit32((code), instr);
}


static inline void emit_mov_wide(
    shellcode_t* code,
    uint8_t opc,        // opcode específico
    bool sf,
    uint8_t hw,
    uint16_t imm16,
    uint8_t Rd)
{
    uint32_t instr = ENCODE_MOV_WIDE(sf, opc, hw, imm16, Rd);
    (code)->Emit32((code), instr);
}
// Opcodes: MOVN = 0b00 (4), MOVZ = 0b10 (5), MOVK = 0b11 (7)
#define MOVZ(code, sf, hw, imm16, Rd) emit_mov_wide(code, 0b10100101, sf, hw, imm16, Rd)
#define MOVN(code, sf, hw, imm16, Rd) emit_mov_wide(code, 0b10010101, sf, hw, imm16, Rd)
#define MOVK(code, sf, hw, imm16, Rd) emit_mov_wide(code, 0b11100101, sf, hw, imm16, Rd)

/**
 * MOV Rd, Rn (alias de ADD Rd, Rn, #0)
 * Solo válido si Rn o Rd es SP (codificado como 31)
 */
static inline void MOV(
    shellcode_t* code,
    bool sf,
    uint8_t Rn,
    uint8_t Rd)
{
    if (Rn != 31 && Rd != 31) {
        fprintf(stderr, "MOV (alias ADD) solo válido si Rd o Rn es SP/WSP (reg 31)\n");
        return;
    }
    // alias de instruccion add:
    ADD_SUB_inmmed(code, false, sf, 0, 0x000, Rn, Rd);
}

// Alias para MOV usando MOVZ cuando se quiera cargar un inmediato
static inline void MOV_IMM(shellcode_t* code, bool sf, uint16_t imm16, uint8_t Rd) {
    // Carga el inmediato con MOVZ, sin shift y sin partes adicionales
    MOVZ(code, sf, 0, imm16, Rd);
}

#define MOV_AUTO(code, sf, Rn, Rd) \
    (((Rn) == 31 || (Rd) == 31) ? MOV(code, sf, Rn, Rd) : MOV_REG(code, sf, Rn, Rd))

#define GET_NUMBER_INSTRUCTIONS(code) (code->size/4)

#endif