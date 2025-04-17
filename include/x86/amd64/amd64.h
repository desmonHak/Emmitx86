#ifndef AMD64_H
#define AMD64_H

#include "global.h"

/**
 * @brief Registers
 * 
 */
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

/**
 * @brief Registers scale
 * 
 */
typedef enum Scale_x64 {
    x1,
    x2,
    x4,
    x8
} Scale_x64;

/**
 * @brief Modes of addressing
 * 
 */
typedef enum Mode_x64 {
    INDIRECT,
    BYTE_DISPLACED_INDIRECT,
    DISPLACED_INDIRECT,
    DIRECT
} Mode_x64;

/**
 * prefijos 0100 WR0B:
 * 0x49 == REX.WB
 * 0x48 == REX.W:
 *          Indica el uso de un prefijo REX que afecta el tamaño del 
 *          operando o la semántica de la instrucción. El orden del 
 *          prefijo REX y otros prefijos de instrucción 
 *          opcionales/obligatorios se describe en el Capítulo 2. 
 *          Tenga en cuenta que los prefijos REX que promueven el 
 *          funcionamiento de las instrucciones heredadas a 64 bits 
 *          no se enumeran explícitamente en la columna de código de 
 *          operación.
 * 
 * Field Name   Bit Position    Definition
 *  -               7:4            0100
 *  W               3               0 = Operand size determined by CS.D
 *                                  1 = 64 Bit Operand Size
 *  R               2               Extension of the ModR/M reg field
 *  X               1               Extension of the SIB index field
 *  B               0               Extension of the ModR/M r/m field, SIB 
 *                                      base field, or Opcode reg field
 * 
 * 
 */
typedef struct PREFIX_REX {
    uint8_t const_field:4; // 0100 
    uint8_t bit_w:1;    /* 0 = Operand size determined by CS.D
                         * 1 = 64 Bit Operand Size
                         */
    uint8_t bit_r:1;    // Extension of the ModR/M reg field
    uint8_t bit_x:1;    // Extension of the SIB index field
    uint8_t bit_b:1;    /* Extension of the ModR/M r/m field, 
                         * SIB base field, or Opcode reg field
                         */
} PREFIX_REX;

/**
 * @brief Permite emitir un ModRM especifico a un codigo
 * 
 * @param code codigo al que emitir el mod/RM
 * @param mod valor mod a dar. 2 bits
 * @param rx valor "reg" a asignar. 3 bits
 * @param rm valor "rm" a asignar. 3 bits
 * 
 * Para las codificaciones Mod/RM que usan registros R8, R9, R10, ...
 * se debera aplicar una operacion AND de la siguiente manera:
 * 
 * R8  AND 7 = 1000 & 111 = 000 = RAX.
 * 
 * R9  AND 7 = 1001 & 111 = 001 = RCX.
 * 
 * R10 AND 7 = 1010 & 111 = 010 = RDX.
 * 
 * R11 AND 7 = 1011 & 111 = 011 = RBX.
 * 
 * R12 AND 7 = 1100 & 111 = 100 = RSP.
 * 
 * R13 AND 7 = 1101 & 111 = 101 = RBP.
 * 
 * R14 AND 7 = 1110 & 111 = 110 = RSI.
 * 
 * R15 AND 7 = 1111 & 111 = 111 = RDI.
 * 
 * 
 * Cuidado con los registros R12 y R13 en algunos modos de direccionamiento como
 * en el indirecto donde el registro RSP(se usa para SIB) y RBP(disp32) se
 * usan para indicar cosas distintas al resto de direccionamientos comunesS
 */
static inline void EmitModRm(shellcode_t *code, uint8_t mod, uint8_t rx, uint8_t rm) {
    /*
     * Mod = 11
     * RM  =        000
     * REG =    001
     * ----------------
     * C8H = 11 001 000
    */
    call(code, Emit8, ((mod << 6) | ((rx & 7) << 3) | (rm & 7)));
}

/**
 * si indirecto con no desplazamiento => mod = 0.
 * si indirecto con 1 byte de desplazamiento => mod = 1.
 * si indirecto con multi-byte(mas de un byte) de desplazamiento => mod = 2.
 * si indirecto con registro de base en el campo RM, exceptuando el registro RSP
 *      En caso de necesitarse coidificacion SIB usar base = 4(0b100), index =
 *      4(0b100), scale = alguna.
 * si es directo => mod = 3.
 */

/**
 * @brief add rax, rcx: rx = rax, operand = rcx
 * 
 * @param code 
 * @param rx 
 * @param operand 
 */
static inline void EmitDirect(shellcode_t *code, uint8_t rx, Regs_x64 operand) {
    EmitModRm(code, DIRECT, rx, operand);
}

/**
 * @brief add rax, [rcx]: rx = RAX, base = RCX
 * 
 * @param code 
 * @param rx 
 * @param base 
 * 
 * El modo indirecto cumple que Mod es 0(INDIRECT). En este modo de 
 * direccionamiento los registros RSP y RBP no codifican un registro base
 * para el direccionamiento indirecto, sino que RSP se usa para indicar
 * si se usara SIB y con ello otros tipos de codificaciones.
 * Mientras que RBP indicara que se usara un disp32(desplazamiento de 32bits)
 * en lugar de un registro.
 * 
 * Estas advertencias se aplcian a los registros extendidos con el prefijo REX,
 * siendo:
 * 
 *      R12 AND 7 = 1100 & 111 = 100 = RSP.
 * 
 *      R13 AND 7 = 1101 & 111 = 101 = RBP.
 * 
 * Por lo tanto se debe tener en cuenta los registros R12, R13, RSP y RBP para
 * este modo de direccionamiento
 */
static inline void EmitIndirect(shellcode_t *code, uint8_t rx, Regs_x64 base) {
    // verificar si es RSP o R12, en ese caso error:
    assert_code((base  & 7) != RSP, code, EmitIndirect_ERROR, 
        return;
    );
    // verificar si es RBP o R13, en cuyo caso indicar error
    assert_code((base  & 7) != RBP, code, EmitIndirect_ERROR, 
        return;
    );
    EmitModRm(code, INDIRECT, rx, base);
}

/**
 * @brief 
 * 
 * @param code 
 * @param rx 
 * @param displacement 
 */
static inline void EmitDiplaced(shellcode_t *code, const uint8_t rx, 
    const uint32_t displacement) {

    EmitModRm(code, INDIRECT, rx, RSP);
    EmitModRm(code, x1, RSP, RBP);
    call(code, Emit32, displacement);       // añadir disp32
}

/**
 * @brief add rax, [0x1235678]: rx = RAX, displacement = 0x1235678
 * 
 * @param code 
 * @param rx 
 * @param displacement 
 */
static inline void EmitIndirectDisplacedRip(shellcode_t *code, uint8_t rx, uint32_t displacement) {
    EmitModRm(code, INDIRECT, rx, RBP);
    call(code, Emit32, displacement);       // añadir disp32
}

/**
 * @brief add rax, [rcx + 0x12]: rx = RAX
 * 
 * @param code 
 * @param rx 
 * @param base 
 * @param displacement 
 */
static inline void EmitIndirectByteDisplaced(shellcode_t *code, uint8_t rx, 
    Regs_x64 base, uint8_t displacement) {

    assert_code((base  & 7) != RSP, code, EmitIndirectByteDisplaced_ERROR, 
        return;
    );

    EmitModRm(code, BYTE_DISPLACED_INDIRECT, rx, base);
    call(code, Emit8, displacement);        // añadir disp8
}

/**
 * @brief add rax, [rcx + 0x1235678]: rx = RAX, base = RCX, displacement =
 *      0x1235678
 * 
 * @param code 
 * @param rx 
 * @param base 
 * @param displacement 
 */
static inline void EmitIndirectDisplaced(shellcode_t *code, uint8_t rx, 
    Regs_x64 base, uint32_t displacement) {

    assert_code((base  & 7) != RSP, code, EmitIndirectDisplaced_ERROR, 
        return;
    );

    EmitModRm(code, DISPLACED_INDIRECT, rx, base);
    call(code, Emit32, displacement);       // añadir disp32
}

/**
 * @brief add rax, [rcx + 4 * rdx ]: rx = RAX, base = RCX, scale = 4
 * 
 * @param code 
 * @param rx 
 * @param base 
 * @param index 
 * @param scale 
 */
static inline void EmitIndirectIndexed(shellcode_t *code, uint8_t rx, 
    Regs_x64 base, Regs_x64 index, Scale_x64 scale) {
    assert_code((base  & 7) != RBP, code, EmitIndirectIndexed_ERROR, 
        return;
    );
    assert_code((index  & 7) != RBP, code, EmitIndirectIndexed_ERROR, 
        return;
    );
    EmitModRm(code, INDIRECT, rx, RSP);
    EmitModRm(code, scale, base, index); // byte SIB
}

/**
 * @brief add rax, [rxc + 4 * rdx + 0x12]: rx = RAX, base = RCX, scale = 4,
 * displacement = 0x12
 * 
 * @param code 
 * @param rx 
 * @param base 
 * @param index 
 * @param scale 
 * @param displacement 
 */
static inline void EmitIndirectIndexedByteDisplaced(shellcode_t *code, 
    uint8_t rx, Regs_x64 base, Regs_x64 index, 
    Scale_x64 scale, uint8_t displacement) {
    EmitModRm(code, BYTE_DISPLACED_INDIRECT, rx, RSP);
    EmitModRm(code, scale, index, base); // byte SIB
    call(code, Emit8, displacement);        // añadir disp8
}

/**
 * @brief add rax, [rxc + 4 * rdx + 0x1235678]: rx = RAX, base = RCX, 
 * scale = 4, displacement = 0x1235678
 * 
 * @param code 
 * @param rx 
 * @param base 
 * @param index 
 * @param scale 
 * @param displacement 
 */
static inline void EmitIndirectIndexedDisplaced(shellcode_t *code, 
    uint8_t rx, Regs_x64 base, Regs_x64 index, 
    Scale_x64 scale, uint32_t displacement) {

    EmitModRm(code, DISPLACED_INDIRECT, rx, RSP);
    EmitModRm(code, scale, index, base);    // byte SIB
    call(code, Emit32, displacement);       // añadir disp32
}

/*
 * el prefijo REX es un byte adicional (de valor entre 0x40 y 0x4F) que permite:
 * Usar registros extendidos (r8 a r15)
 * Usar instrucciones de 64 bits
 * Extender los campos ModRM y SIB para direccionamiento
 * Acceder a registros altos (SPL, BPL, etc.)
 * 
 *    0100WRXB
 *     | | |
 *     | | +-- B: extiende el campo 'rm'/'base'
 *     | +---- X: extiende el campo 'index'
 *     +------ R: extiende el campo 'reg'
 * 
*/

/**
 * @brief 0x48 = 01001000b: REX con W=1 (modo 64 bits), R=0, X=0, B=0. <
 * 
 * (base >> 3): saca el bit 3 del registro base → lo pone como bit B.
 * 
 * ((index >> 3) << 1): saca el bit 3 del registro índice → lo pone como bit X.
 * 
 * ((rx >> 3) << 2): saca el bit 3 del registro destino (reg) → lo pone como bit R.
 * 
 * Ejemplo:
 * 
 * rx = r10 (valor 10), base = r13 (valor 13), index = r8 (valor 8).
 * 
 * Resultado: se emite 0x4F → REX con W=1, R=1, X=1, B=1.
 * 
 * @param code codigo al que agregar el prefijo rex
 * @param rx 
 * @param base 
 * @param index 
 */
static inline void EmitRexIndexed(shellcode_t *code,  Regs_x64 rx, Regs_x64 base, Regs_x64 index) {
    call(code, Emit8, 0x48 | (base >> 3) | ((index >> 3) << 1) | ((rx >> 3) << 2) );
}

/**
 * @brief Esta versión no incluye el bit X (índice) y es una version
 * simplificada de EmitRexIndexed. Solo:
 * 
 *     base >> 3 → B.
 * 
 *     rx >> 3 << 2 → R.
 * 
 * @param code codigo al que agregar el prefijo rex
 * @param rx 
 * @param base 
 */
static inline void EmitRex(shellcode_t *code,  Regs_x64 rx, Regs_x64 base) {
    call(code, Emit8, 0x48 | (base >> 3) | ((rx >> 3) << 2) );
}


#endif
