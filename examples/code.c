#include "x86/amd64/amd64.h"

int main(int argc, char **argv) {

    shellcode_t my_shellcode = init_shellcode();
    shellcode_t *ptr_sc = &my_shellcode;
    ptr_sc->capacity = 16;
    call(ptr_sc, expand);

    EMIT_MOV_R_I(ptr_sc, RBX, 0x12345678deadbeefull);
    EMIT_MOV_RAX_OFF(ptr_sc, 0x12345678deadbeefull);
    EMIT_MOV_OFF_RAX(ptr_sc, 0x12345678deadbeefull);
    EMIT_R_R(ptr_sc, MOV, RAX, R10);
    EMIT_M_R(ptr_sc, MOV, RAX, R10);
    EMIT_I(ptr_sc, JMP, 0x1234);
    EMIT_C_I(ptr_sc, J, NZ, 0x1234);
    EMIT_C_I(ptr_sc, J, NZ, 0x1234);
    EMIT_C_I(ptr_sc, J, NZ, 0x1234);

    EMIT_INM(ptr_sc, CLC);
    EMIT_INM(ptr_sc, STC);
    EMIT_INM(ptr_sc, CLI);
    EMIT_INM(ptr_sc, STI);
    EMIT_INM(ptr_sc, CLD);
    EMIT_INM(ptr_sc, STD);
    EMIT_INM(ptr_sc, CPUID);

    EMIT_D_I(ptr_sc, ADD, 0x12345678, 0xDEADBEEF)

    for (Regs_x64 destination = RAX; destination <= R15; destination++) {
        EMIT_X_R(ptr_sc, MUL, destination);
        EMIT_R_I(ptr_sc, ADD, destination, 0x12345678);
        if ((destination  & 7)  != RSP){
            EMIT_MD_I(ptr_sc, ADD, destination, 0x12, 0xDEADBEEF);
            EMIT_MD1_I(ptr_sc, ADD, destination, 0x12345678, 0xDEADBEEF);   
        }
        if ((destination & 7) != RBP) {
            EMIT_SIB_I(ptr_sc, ADD, destination, x4, R8, 0xDEADBEEF);
        }
        

        EMIT_R_RIPD(ptr_sc, ADD, destination, 0x12345678);
        EMIT_R_D(ptr_sc, ADD, destination, 0x12345678);
        EMIT_RIPD_R(ptr_sc, ADD, 0x12345678, destination);
        EMIT_D_R(ptr_sc, ADD, 0x12345678, destination);

        for (Regs_x64 source = RAX; source <= R15; source++) {
            EMIT_R_R(ptr_sc, ADD, destination, source);

            // el index no puede ser RBP o se realiza un disp32 en el SIB,
            // mismo caso con la base para la funcion EmitIndirectIndexed
            if ((source  & 7)  != RBP && (destination & 7) != RBP) {
                EMIT_X_SIB(ptr_sc, MUL, destination, x4, R8)
                EMIT_X_SIBD1(ptr_sc, MUL, destination, x4, R8, 0x12)
                EMIT_X_SIBD(ptr_sc, MUL, destination, x4, R8, 0x12345678)
                EMIT_R_SIB(ptr_sc, ADD, destination, source, x4, destination);
                EMIT_SIB_R(ptr_sc, ADD, destination, x4, source, source);
            }
            EMIT_SIBD_R(ptr_sc, ADD, destination, x4, source, 
                0x12345678, source);
            
            if ((source  & 7)  != RBP){
                EMIT_R_SIBD1(ptr_sc, ADD, destination, source, 
                    x4, destination , 0x12);

                EMIT_R_SIBD(ptr_sc, ADD, destination, source, 
                    x4, destination, 0x12345678);
            } 
            if ((destination  & 7)  != RBP){
                EMIT_SIBD1_R(ptr_sc, ADD, destination, x4, source, 
                    0x12, source);

               
            }

            if ((source & 7) != RSP && (source  & 7)  != RBP) {
                EMIT_R_M(ptr_sc, ADD, destination, source);
                EMIT_R_MD1(ptr_sc, ADD, destination, source, 0x12);
                EMIT_R_MD(ptr_sc, ADD, destination, source, 0x12345678);
            }
            if ((destination & 7) != RSP && (destination  & 7)  != RBP){
                EMIT_X_MD1(ptr_sc, MUL, destination,  0x12);
                EMIT_X_MD(ptr_sc, MUL, destination,  0x12345678)
                EMIT_X_M(ptr_sc, MUL, destination);
                EMIT_M_R(ptr_sc, ADD, destination, source)
                EMIT_MD1_R(ptr_sc, ADD, destination, 0x12, source);
                EMIT_MD_R(ptr_sc, ADD, destination, 0x12345678, source); 
            }
            if ((source & 7) != RBP) {
                EMIT_R_SIB(ptr_sc, ADD, destination, source, x1, RSP)
            }
            if (ptr_sc->err != 0) {
                printf("Error con codigo: %d\n", ptr_sc->err);
                goto jump_exit_loops;
            }
        }
    }

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