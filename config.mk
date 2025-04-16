CC 			  = gcc
ARR			  = ar

VESRION_C     = 11

PATH_SRC 	      = src
PATH_INCLUDE      = include
PATH_EXAMPLES	  = examples
PATH_DEBUG 		  = DebugLibC
PATH_COLORS		  = $(PATH_DEBUG)/colors-C-C-plus-plus

LINKER_FLAGS  	  =  -L. -lEmmitx86

INCLUDE_FLAGS = -I. -I$(PATH_INCLUDE)
GLOBAL_CFLAGS = -std=c$(VESRION_C) $(INCLUDE_FLAGS) -masm=intel \
				-D_ExceptionHandler -fdiagnostics-color=always -D_GNU_SOURCE $(DEBUG_LINUX)

CFLAGS_F  	  =  $(GLOBAL_CFLAGS) -O3 -Wno-unused-parameter \
				-Wno-implicit-fallthrough -Wno-type-limits  \
				-Wno-unused-variable -Wno-pointer-sign 
CFLAGS_DEBUG  =  $(GLOBAL_CFLAGS) -ggdb -fno-asynchronous-unwind-tables  	    	\
				-Wall -Wextra -pipe -O0 -D DEBUG_ENABLE      	          			\
				-fstack-protector-strong -Wpedantic -fno-omit-frame-pointer       	\
				-fno-inline -fno-optimize-sibling-calls -fdiagnostics-show-option 	\
				-fPIC -DDEBUG_VECTOR_LIST

MODE_GEN_LIB ?= release

ifeq ($(MODE_GEN_LIB),debug)
  CFLAGS := $(CFLAGS_DEBUG)
else
  ifeq ($(MODE_GEN_LIB),gprof)
    CFLAGS := $(CFLAGS_DEBUG) -pg -fprofile-arcs -fprofile-arcs -g
  else
    CFLAGS := $(CFLAGS_F)
  endif
endif


ARR_FLAGS     = -rc

CFLAGS_EXAMPLES = $(CFLAGS) -save-temps -g -D DEBUG_ENABLE $(LINKER_FLAGS)

# Buscar todos los archivos .c en subdirectorios de src/x86 (un nivel)
SOURCES   := $(wildcard $(PATH_SRC)/x86/*/*.c) $(wildcard $(PATH_SRC)/*.c)
# Generar la lista de objetos a partir de los .c encontrados. Por ejemplo, src/x86/amd64/amd64.c -> src/x86/amd64/amd64.o
OBJECTS   := $(SOURCES:.c=.o)