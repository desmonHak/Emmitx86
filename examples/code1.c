#include "x86/amd64/amd64.h"

#ifdef _WIN32
#include <windows.h>


// Tokenizer
char current_charter; // catacter actual
char* remaining_charters = NULL; // resto de caracetres

#define Assert(condition, ...)              \
if (!(condition)) {                         \
    __VA_ARGS__                             \
}

#define create_err_code(name) name ##_ERROR
typedef enum errors_code {
    NO_ERROR_CODE,
    create_err_code(ReadCharacter),
    create_err_code(StartReadingFromFile),
    create_err_code(AllocateRegister),
    create_err_code(FreeRegister),
    create_err_code(GetRegister)
} errors_code;

errors_code c_error = NO_ERROR_CODE;

void ReadCharacter() {
    Assert(current_charter, 
        c_error = create_err_code(ReadCharacter);
        return;
    )
    current_charter = *remaining_charters;
    remaining_charters++;
}


typedef enum Token {
    TOKEN_EOF,

    // aqui los tokens literales

    LAST_LITERAL_TOKEN = 127,
    TOKEN_IDENTIFIER,
    TOKEN_INTEGER

} Token;

Token token;
uint64_t token_integer;

void ReadToken() {
    retry:
        switch (current_charter) {
            case TOKEN_EOF:
                token = TOKEN_EOF; break;

            case ' ':
            case '\n':
            case '\r':
            case '\t':
            case '\v': 
                // saltar los caracteres y repetir
                ReadCharacter(); // leer el siguiente caracter antes
                // de repetir
                goto retry;
            
            case '(':
            case ')':
            case '*':
            case '+':
            case '/':
            case '-':
            case '^':
                token = current_charter;
                ReadCharacter();
                break;

            case '0' ... '9':
                token = TOKEN_INTEGER;
                token_integer = current_charter - '0';
                ReadCharacter(); 
                while(isdigit(current_charter)) {
                    token_integer *= 10;
                    token_integer += current_charter - '0';
                    ReadCharacter(); // leer el siguiente caracter
                }
                break;
        }
}

void EspectToken(Token expected_token) {
    Assert(expected_token);
    ReadToken();
}




/*Regs_x64 next_register = 0;
Regs_x64 AllocateRegister(){
    Assert(next_register <= R15, 
        c_error = create_err_code(AllocateRegister);
        return 0;
    )

    Regs_x64  current_register = next_register;
    next_register++;
    return current_register;
}
void FreeRegister() {
    Assert(next_register >= RAX, 
        c_error = create_err_code(FreeRegister);
        return;
    )
    next_register--;
}    
*/



/**
 * @brief Registros generales disponibles, los ponemos en orden inverso
 * ya que los registros R8 a R15 no son usados por instrucciones, por lo que 
 * tenemos total libertad de uso con ellos. No como con RAX que se utilzia en
 * operaciones como MUL.
 * 
 */
Regs_x64 first_temporary_register = R15;



Regs_x64 GeyNextTemporaryRegister(Regs_x64 current_register){
    Assert(current_register > R8, 
        c_error = create_err_code(GetRegister);
        return 0;
    )
    return current_register-1;
}



/**

    Parsing expressions by precedence climbing

    GRAMATICA:

    notacion:
        | -> O

    y un factor puede ser:
        factor = integer | (expresion)

    y un termino puede ser:
        termino = factor | termino * factor | termino / factor

    una expresion puede ser:
        expresion = termino | esprecion + termino | expresion - termino

    a-b-c = (a - b) (-c)


    Los factores son los elementos más simples (números o expresiones entre paréntesis).

    Los términos combinan factores usando multiplicación o división.

    Las expresiones combinan términos usando suma o resta.


    Asociación recursiva izquierda vs derecha

    Asociación en gramáticas y parsers se refiere a cómo se agrupan los 
    operadores del mismo nivel de precedencia cuando aparecen en secuencia. 
    Por ejemplo, en la expresión a - b - c, 
    ¿se interpreta como (a - b) - c (asociación izquierda) o 
    como a - (b - c) (asociación derecha)?

    Asociación izquierda:
        Los operadores se agrupan desde la izquierda.
        Ejemplo: a - b - c se interpreta como (a - b) - c.

    Asociación derecha:
        Los operadores se agrupan desde la derecha.
        Ejemplo: a - b - c se interpreta como a - (b - c).


*/
void ParseExpresion(shellcode_t *ptr_sc, Regs_x64 destination);

void ParseAtom(shellcode_t *ptr_sc, Regs_x64 destination) {
    if (token == TOKEN_INTEGER) {
        ReadToken();
        EMIT_MOV_R_I(ptr_sc, destination, token_integer)
        
    } else if (token == '(') {
        ReadToken();
        ParseExpresion(ptr_sc, destination);
        EspectToken(')');
    }

}

#if 0
Regs_x64 ParseFactor(shellcode_t *ptr_sc) {
    Regs_x64 target_register = ParserPower(ptr_sc);
    if (token == '^') {
        ReadToken();
        uint64_t power = ParseFactor(ptr_sc);

        uint64_t base = value;
        value = 1;
        for (uint64_t i = 0; i < power; i++){
            value *= base;
        }
    }
    return target_register;
    
}
#endif

/**
 * @brief Permite procesar un termino(multiplicacion o division).
 * 
 * # Problemas:
 * 
 *      La instruccion MUL de x64 ocupa el registro RAX para realizar las 
 *      multiplicaciones, y el registro RDX para devolver el resultado, 
 *      destruyendo lo que hubiera en el anteriormente.
 * 
 *      ## Estrategia
 *          1. Podemos usar la instruccion XCHG para intercambiar los valores.
 *          Si el operando no es RAX, se usara un registro temporal para 
 *          almacenar lo que ya hubiera en RAX anteriormente, ya que RAX es el
 *          primer registro. 
 *          2. mover lo que se indicara en el registro de destino a RAX
 * 
 * @param ptr_sc shellcode al que emitir codigo
 * @param destination registro de destino.
 */
void ParseTerm(shellcode_t *ptr_sc, Regs_x64 destination) {
    ParseAtom(ptr_sc, destination);
    while (token == '*' || token == '/'){
        Token operator_token = token; // almacenar el token de operacion
        ReadToken();
        Regs_x64 operand = GeyNextTemporaryRegister(destination);
        ParseAtom(ptr_sc, operand);

        // MOV  RAX,      reg1
        EMIT_R_R(ptr_sc, MOV, RAX, destination); 
        if (operator_token == '*') {
            EMIT_X_R(ptr_sc, MUL, operand);
        } else if (operator_token == '/') {
            EMIT_X_R(ptr_sc, DIV, operand);
        } else {
            puts("Err");
        }
        // MOV  reg1,     RAX
        EMIT_R_R(ptr_sc, MOV, destination, RAX); 
    }

}

/**
 * @brief función ParseExpresion está implementando asociación izquierda para
 * los operadores - (y, por extensión, +):
 * 
 * @return uint64_t 
 */
void ParseExpresion(shellcode_t *ptr_sc, Regs_x64 destination){
    // se lee el primer termino
    ParseTerm(ptr_sc, destination);

    /*
    y se itera los siguientes terminos
    Así, en a - b - c, la ejecución es:
        - value = a
        - value = value - b → ahora value = a - b
        - value = value - c → ahora value = (a - b) - c

    Esto es asociación por la izquierda.
    */
    while (token == '-' || token == '+') {
        Token operator_token = token; // almacenar el token de operacion
        ReadToken();
        Regs_x64 operand =  GeyNextTemporaryRegister(destination);
        ParseTerm(ptr_sc, operand);
        if (operator_token == '+') {
            EMIT_R_R(ptr_sc, ADD, destination, operand)
        } else {
            EMIT_R_R(ptr_sc, SUB, destination, operand)
        }
    }
}


/**
 * @brief Construct a new Start Reading From File object.
 * 
 * 1. Rendimiento y paso cero-copias
 * 
 * 1.1 Evita copias de búferes explícitas
 * Al usar mmap/MapViewOfFile, los datos del archivo pueden leerse “in-place” 
 * sin copiar primero bloques desde el kernel a búferes de usuario, lo cual 
 * elimina la sobrecarga de las llamadas read()/write() que copian datos 
 * hacia/desde la dirección de usuario.
 * 
 * 1.2 Menos transiciones usuario-kernel
 * Cada acceso a una página mapeada provoca una falta de página que el 
 * kernel resuelve directamente, en lugar de repetir llamadas a read()/write(). 
 * Esto reduce el número de transiciones costosas entre espacio de usuario y 
 * kernel.
 * 
 * 1.3 Aprovecha la caché y el prefetch del SO
 * El Cache Manager de Windows maneja la caché de disco y realiza “read-ahead” 
 * automáticamente. Una vez que una página está en memoria, futuros accesos no 
 * requieren ir al disco ni generar nuevas faltas de página 
 * 
 * 2. Acceso aleatorio y simplificación del código
 * 
 * 2.1 Sin gestión manual de punteros de archivo
 * 
 * Con fopen y fread, para acceder a una posición arbitraria se usa fseek 
 * seguido de fread. Con MMF basta con calcular un offset en el puntero 
 * devuelto por MapViewOfFile, como si fuera un array en memoria.
 * 
 * 2.2 Lógica de programa más clara
 * El modelo de “memoria como búfer” elimina la necesidad de bucles de 
 * lectura/escritura y comprobaciones de retorno en cada llamada
 * 
 * 3. Compartición y copia-en-escritura
 * 
 * 3.1 Compartir datos entre procesos
 * 
 * Los objetos de mapeo (CreateFileMapping) pueden nombrarse y reutilizarse en 
 * múltiples procesos, lo que facilita la comunicación y reduce la duplicación 
 * de datos.
 * 
 * 3.2 Mecanismo de Copy-on-Write
 * Con la protección PAGE_WRITECOPY, múltiples procesos pueden mapear el mismo 
 * archivo en modo lectura/escritura sin interferir; si alguno escribe, el SO 
 * crea una copia privada de la página para ese proceso, manteniendo el archivo
 * original intacto 
 * 
 * @param filename 
 */
void* StartParsingFile(const char* filename) {
    HANDLE file = CreateFileA(
        filename,               // nombre del fichero
        GENERIC_READ,           // acceso: sólo lectura
        FILE_SHARE_READ,        // compartir: otros procesos pueden leer
        NULL,                   // atributos de seguridad: predeterminados
        OPEN_EXISTING,          // sólo si existe
        FILE_ATTRIBUTE_NORMAL,  // atributos normales
        NULL                    // sin handle de plantilla
    );
    Assert(file != INVALID_HANDLE_VALUE, 
        c_error = create_err_code(StartReadingFromFile);
        return NULL;
    )

    DWORD file_size = GetFileSize(file, NULL);

    /*
     * Creamos un objeto de mapeo. permitiría lectura/escritura directa; 
     * PAGE_WRITECOPY habilita copia-en-escritura (“copy-on-write”), de modo 
     * que las escrituras no se propaguen al archivo original.
     * Los ceros en tamaño (dwMaximumSizeHigh/Low) indican que el mapeo cubrirá 
     * todo el archivo existente.
     */
    HANDLE file_mapping = CreateFileMappingA(
        file,
        NULL,                   // seguridad: predeterminada
        PAGE_WRITECOPY,         // protección
        0, 0,                   // mapear todo el archivo
        NULL                    // sin nombre
    );
    Assert(file_mapping != INVALID_HANDLE_VALUE, 
        CloseHandle(file);
        c_error = create_err_code(StartReadingFromFile);
        return NULL;
    )

    /*
     * Mapeo en el espacio de direcciones. Idealmente se usarían los flags 
     * FILE_MAP_READ y/o FILE_MAP_WRITE, pero aquí usan las constantes de 
     * acceso genérico. 
     * Pasar ceros hace que el sistema elija automáticamente el offset 
     * (inicio del archivo) y el tamaño (toda la longitud).
     */
    void* file_memory = MapViewOfFileEx(
        file_mapping, 
        FILE_MAP_COPY, 
        0, 0,                   // offset alto/bajo = 0
        0,                      // mapear todo
        NULL                    // dirección sugerida = que el SO elija
    );
    Assert(file_memory, 
        CloseHandle(file_mapping);
        c_error = create_err_code(StartReadingFromFile);
        return NULL;
    )

    Assert(file_size > 0);
    Assert(((char*)file_memory)[file_size - 1] == '\n')

    // poner terminador nulo al final del archivo:
    ((char*)file_memory)[file_size - 1] = '\0';
    current_charter = *(char*)file_memory;
    remaining_charters = file_memory + 1    ;
    ReadToken(); // analizar el primer token

    return file_memory;
}


int main(int argc, char **argv){

    shellcode_t my_shellcode = init_shellcode();
    shellcode_t *ptr_sc = &my_shellcode;
    call(ptr_sc, expand);


    StartParsingFile("test.cd");
    Assert(c_error == 0,
        printf("Error con codigo: %d %d, remaining_charters = %p\n", c_error, GetLastError(), remaining_charters);
        goto jump_exit_loops;
    )
    

    ParseExpresion(ptr_sc, first_temporary_register);
    //printf("result %llu\n", result);



    if (ptr_sc->err != 0) {
        printf("Error con codigo: %d\n", ptr_sc->err);
        goto jump_exit_loops;
    }


    jump_exit_loops:
    call(ptr_sc, dump);

    // objdump -D -b binary -M intel -m i386:x86-64 shellcode1.bin > output1.asm
    FILE *f = fopen("shellcode1.bin", "wb");
    fwrite(ptr_sc->code, ptr_sc->size, 1, f);
    fclose(f);

    int exit_code = ptr_sc->err;
    call(ptr_sc, free);
    puts("Exit...");
    return exit_code;


}
#else
int main() {
    puts("Este codigo usa Windows.h");
    return 0;
}
#endif