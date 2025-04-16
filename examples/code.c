#include "x86/amd64/amd64.h"

int main() {

    shellcode_t my_shellcode = init_shellcode();
    shellcode_t *ptr_sc = &my_shellcode;
    ptr_sc->capacity = 16;
    call(ptr_sc, expand);

    for (Regs_x64 destination = RAX; destination <= R15; destination++) {
        EmitRex(ptr_sc, destination, 0);
        op_reg(ADD)(ptr_sc);
        EmitIndirectDisplacedRip(ptr_sc, destination, 0x12345678);

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

            if ((source  & 7)  != RBP){
                EmitRexIndexed(ptr_sc, destination, source, destination);
                op_reg(ADD)(ptr_sc);
                EmitIndirectIndexed(ptr_sc, destination, source, destination, x4);

                EmitRexIndexed(ptr_sc, destination, source, destination);
                op_mem(ADD)(ptr_sc);
                EmitIndirectIndexed(ptr_sc, destination, source, destination, x8);
            } else {
                EmitRexIndexed(ptr_sc, destination, source, destination);
                op_reg(ADD)(ptr_sc);
                EmitIndirectIndexedByteDisplaced(ptr_sc, destination, source, 
                    destination, x4, 0x87);

                EmitRexIndexed(ptr_sc, destination, source, destination);
                op_mem(ADD)(ptr_sc);
                EmitIndirectIndexedByteDisplaced(ptr_sc, destination, source, 
                    destination, x4, 0x87);


            }

            if ((source & 7) != RSP && (source  & 7)  != RBP) {
                // R11? R12?
                EMIT_R_M(ptr_sc, ADD, destination, source)
                /*EmitRex(ptr_sc, destination, source);
                op_reg(ADD)(ptr_sc);
                EmitIndirect(ptr_sc, destination, source);*/

                EmitRex(ptr_sc, destination, source);
                op_mem(ADD)(ptr_sc);
                EmitIndirect(ptr_sc, destination, source);

                EMIT_R_MD1(ptr_sc, ADD, destination, source, 0x12);
                /*
                EmitRex(ptr_sc, destination, source);
                op_reg(ADD)(ptr_sc);
                EmitIndirectByteDisplaced(ptr_sc, destination, source, 0x12);*/

                EmitRex(ptr_sc, destination, source);
                op_mem(ADD)(ptr_sc);
                EmitIndirectByteDisplaced(ptr_sc, destination, source, 0x12);

                EMIT_R_MD(ptr_sc, ADD, destination, source, 0x12345678)
                /*EmitRex(ptr_sc, destination, source);
                op_reg(ADD)(ptr_sc);
                EmitIndirectDisplaced(ptr_sc, destination, source, 0x12345678);*/

                EmitRex(ptr_sc, destination, source);
                op_mem(ADD)(ptr_sc);
                EmitIndirectDisplaced(ptr_sc, destination, source, 0x12345678);
            }
            if ((source & 7) == RSP) {
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