#include "arm/aarch64/aarch64.h"

int main(int argc, char **argv) {

    shellcode_t my_shellcode = init_shellcode();
    shellcode_t *ptr_sc = &my_shellcode;
    ptr_sc->capacity = 16;
    call(ptr_sc, expand);


    ADD_inmmed(ptr_sc, true, false, 0, 0, 0);
    ptr_sc->Emit32(ptr_sc, 0x91000011);

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