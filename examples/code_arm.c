#include "arm/aarch64/aarch64.h"

int main(int argc, char **argv) {

    shellcode_t my_shellcode = init_shellcode();
    shellcode_t *ptr_sc = &my_shellcode;
    ptr_sc->capacity = 16;
    call(ptr_sc, expand);


    //ADD_inmmed(ptr_sc, true, false, 0xffff, R30, R30);

    // 1. MOV_REG (alias ORR Rd, Rn, Rn) para mover R30 a R25
    MOV_REG(ptr_sc, 1, R30, R25);

    // 2. ADD_inmmed: ADD X0, X1, #0x123 (64-bit, sin shift)
    ADD_SUB_inmmed(ptr_sc, false, true, false, 0x123, R1, R0);

    // 3. SUB_inmmed: SUB W2, W3, #0x10 (32-bit, sin shift)
    ADD_SUB_inmmed(ptr_sc, true, false, false, 0x10, R3, R2);

    // 4. CMP (alias SUBS Rd=XZR)
    CMP(ptr_sc, true, R4, 0x1F);  // Comparar R4 con 0x1F

    // 5. AND (operación lógica registro)
    AND(ptr_sc, true, R5, R6, R7);

    // 6. LSL (shift lógico a la izquierda)
    // 64-bit LSL x9, x8, #4
    // UBFM X9, X8, #60, #59   ; que equivale a LSL #4
    LSL_inmmed(ptr_sc, true, R8, R9, 4);


    // 7. B (salto incondicional relativo)
    // Salto de +4 instrucciones (4 * 4 = 16 bytes) → imm26 = 4
    B(ptr_sc, 4);

    // 8. LDR
    // 4B F1 4F F8    ldur x11, [x10, #0xff]
    LDR_PRE_inmmed(ptr_sc, 1, 0xff, R10, R11);  

    // 9. CBZ (comparar con cero y saltar)
    // 5instrucciones * 4bytes cada una == 0x14
    CBZ(ptr_sc, true, R12, 5);

    // 10. NOP (sin operación)
    NOP(ptr_sc);

    // 11. MOV wide: MOVZ X13, #0x1234, hw=1 (inserta inmediato a bits 16-31)
    MOVZ(ptr_sc, true, 1, 0x1234, R13);

    // Fin: RET
    RET(ptr_sc);

    printf("Se genero %d de instrucciones de 32bits\n", GET_NUMBER_INSTRUCTIONS(ptr_sc));
    jump_exit_loops:
    call(ptr_sc, dump);

    // objdump -D -b binary -M intel -m i386:x86-64 shellcode.bin > output.asm
    FILE *f = fopen("shellcode.bin", "wb");
    fwrite(ptr_sc->code, ptr_sc->size, 1, f);
    fclose(f);

    int exit_code = ptr_sc->err;
    call(ptr_sc, free);
    puts("Exit...");
    return exit_code;
}