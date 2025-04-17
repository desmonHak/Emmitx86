#include "x86/amd64/amd64.h"

int main() {

    shellcode_t my_shellcode = init_shellcode();
    shellcode_t *ptr_sc = &my_shellcode;
    ptr_sc->capacity = 16;
    call(ptr_sc, expand);

    for (Regs_x64 destination = RAX; destination <= R15; destination++) {
        //EmitRex(ptr_sc, destination, 0);
        //op_reg(ADD)(ptr_sc);
        //EmitIndirectDisplacedRip(ptr_sc, destination, 0x12345678);

        EMIT_R_I(ptr_sc, ADD, destination, 0x12345678);
        if ((destination  & 7)  != RSP){
            EMIT_MD_I(ptr_sc, ADD, destination, 0x12, 0xDEADBEEF);
            EMIT_MD1_I(ptr_sc, ADD, destination, 0x12345678, 0xDEADBEEF);
            
            
        }
        if ((destination & 7) != RBP) {
            EMIT_SIB_I(ptr_sc, ADD, destination, x4, R8, 0xDEADBEEF);
        }

        EmitRex(ptr_sc, destination, 0);
        op_mem(ADD)(ptr_sc);
        EmitIndirectDisplacedRip(ptr_sc, destination, 0x12345678);

        EmitRex(ptr_sc, destination, 0);
        op_reg(ADD)(ptr_sc);
        EmitDiplaced(ptr_sc, destination, 0x12345678);

        for (Regs_x64 source = RAX; source <= R15; source++) {
            /*call(ptr_sc, Emit8, 0x48); // REX
            call(ptr_sc, Emit8, 0x03); // ADD
            
            EmitRex(ptr_sc, destination, source);
            op_reg(ADD)(ptr_sc);
            EmitDirect(ptr_sc, destination, source);
            */
            EMIT_R_R(ptr_sc, ADD, destination, source);

            EmitRex(ptr_sc, destination, source);
            op_mem(ADD)(ptr_sc); 
            EmitDirect(ptr_sc, destination, source);

            // el index no puede ser RBP o se realiza un disp32 en el SIB,
            // mismo caso con la base para la funcion EmitIndirectIndexed
            if ((source  & 7)  != RBP && (destination & 7) != RBP) {
                EMIT_R_SIB(ptr_sc, ADD, destination, source, x4, destination);
                EMIT_SIB_R(ptr_sc, ADD, destination, x4, source, source);
            }
            if ((source  & 7)  != RBP){
                EMIT_R_SIBD1(ptr_sc, ADD, destination, source, 
                    x4, destination , 0x12);

                EMIT_R_SIBD(ptr_sc, ADD, destination, source, 
                    x4, destination, 0x12345678);
            } 
            if ((destination  & 7)  != RBP){
                EMIT_SIBD1_R(ptr_sc, ADD, destination, x4, source, 
                    0x12, source);

                EMIT_SIBD_R(ptr_sc, ADD, destination, x4, source, 
                    0x12345678, source);
            }

            if ((source & 7) != RSP && (source  & 7)  != RBP) {
                // R11? R12?
                /*EmitRex(ptr_sc, destination, source);
                op_reg(ADD)(ptr_sc);
                EmitIndirect(ptr_sc, destination, source);*/

                /*EmitRex(ptr_sc, destination, source);
                op_mem(ADD)(ptr_sc);
                EmitIndirect(ptr_sc, destination, source);*/

                EMIT_R_MD1(ptr_sc, ADD, destination, source, 0x12);
                /*
                EmitRex(ptr_sc, destination, source);
                op_reg(ADD)(ptr_sc);
                EmitIndirectByteDisplaced(ptr_sc, destination, source, 0x12);*/

                
                /*EmitRex(ptr_sc, destination, source);
                op_mem(ADD)(ptr_sc);
                EmitIndirectByteDisplaced(ptr_sc, destination, source, 0x12);*/

                EMIT_R_MD(ptr_sc, ADD, destination, source, 0x12345678)
                /*EmitRex(ptr_sc, destination, source);
                op_reg(ADD)(ptr_sc);
                EmitIndirectDisplaced(ptr_sc, destination, source, 0x12345678);*/

                
                /*EmitRex(ptr_sc, destination, source);
                op_mem(ADD)(ptr_sc);
                EmitIndirectDisplaced(ptr_sc, destination, source, 0x12345678);*/

            }
            if ((destination & 7) != RSP && (destination  & 7)  != RBP){
                EMIT_M_R(ptr_sc, ADD, destination, source );
                EMIT_MD1_R(ptr_sc, ADD, destination, 0x12, source);
                EMIT_MD_R(ptr_sc, ADD, destination, 0x12345678, source);
                
            }
            if ((source & 7) != RBP) {
                EmitRex(ptr_sc, destination, source);
                op_reg(ADD)(ptr_sc);
                EmitIndirectIndexed(ptr_sc, destination, source, RSP, x1);
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