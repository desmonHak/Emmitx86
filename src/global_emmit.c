#ifndef EMMIT_GLOBAL_C
#define EMMIT_GLOBAL_C

#include "global_emmit.h"

static void Emit8(shellcode_t* code, uint8_t byte) {
    if (code->capacity <= code->size + sizeof(uint8_t)) {
        call(code, expand);
    }
    code->code[code->size++] = byte;
}

static void Emit32(shellcode_t* code, uint32_t bytes) {
    if (code->capacity <= code->size + sizeof(uint32_t)) {
        call(code, expand);
    }
    *((uint32_t *)&(code->code[code->size])) = bytes;
    code->size += sizeof(uint32_t);
}

static void Emit64(shellcode_t* code, uint64_t bytes) {
    if (code->capacity <= code->size + sizeof(uint64_t)) {
        call(code, expand);
    }
    *((uint64_t *)&(code->code[code->size])) = bytes;
    code->size += sizeof(uint64_t);
}

// Función expand: redimensiona el buffer 'code'
static void expand(shellcode_t* code) {
    // Política de expansión: duplicamos la capacidad actual o asignamos un valor inicial si es 0.
    size_t newCapacity = (code->capacity > 0) ? (code->capacity * 2) : 64;
    uint8_t *newCode = realloc(code->code, newCapacity);
    if (newCode == NULL) {
        code->err = REALLOC_ERROR;
        return; // retornar sin hacer nada mas que cambiar el estado de error
    }
    code->code = newCode;
    code->capacity = newCapacity;
    
    code->err = NO_ERROR_SC;
}

/**
 * @brief Solo libera el contenido de una estructura de tipo shellcode
 * mas no la estructura en si misma si fue reservada usando mem dinamica.
 * 
 * @param code codigo a liberar
 */
static void freeSC(shellcode_t* code){
    if (code == NULL) return;
    if (code->code != NULL) {
        free(code->code);
    }  
    code->code = NULL;
    code->capacity = 0;
    code->size = 0;
    code->err = 0;
}

static void DumpBytes(const shellcode_t *shell) {
    size_t i;
    
    for (i = 0; i < shell->size; i++) {
        // Imprimir offset al inicio de cada línea (cada 8 bytes)
        if (i % 8 == 0) {
            // Si no es la primera línea, saltar línea
            if (i != 0) {
                printf("\n");
            }
            printf("[%04zx]: ", i);
        }
        // Imprimir cada byte en formato hexadecimal (2 dígitos en mayúsculas)
        printf("%02X ", shell->code[i]);
    }
    printf("\n");
}

shellcode_t init_shellcode() {
    return (shellcode_t) {
        .capacity = 0,
        .code     = NULL,
        .Emit64   = Emit64,
        .Emit32   = Emit32,
        .Emit8    = Emit8,
        .err      = 0,
        .expand   = expand,
        .size     = 0,
        .free     = freeSC,
        .dump     = DumpBytes
    };
}
#endif