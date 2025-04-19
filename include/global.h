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


#endif