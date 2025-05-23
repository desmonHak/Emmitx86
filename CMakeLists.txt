cmake_minimum_required(VERSION 3.28)
project(Emmitx86 C)

set(CMAKE_C_STANDARD 11)

include_directories(include)
include_directories(include/x86)
include_directories(include/x86/amd64)

add_executable(code
        examples/code.c
        include/x86/amd64/amd64.h
        include/x86/global_x86.h
        include/global.h
        src/x86/amd64/amd64.c
        src/global.c)

add_executable(code1
        examples/code1.c
        include/x86/amd64/amd64.h
        include/x86/global_x86.h
        include/global.h
        src/x86/amd64/amd64.c
        src/global.c)