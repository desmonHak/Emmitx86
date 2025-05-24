UPLOAD_ANDROID	= 	adb push $@    /data/local/tmp/
CC			 	=	wsl --cd "/mnt/f/C/Emmitx86" aarch64-linux-gnu-gcc -static
TARGET 		 	=	libEmmitx86
RM 			 	=	wsl rm
RMFLAGS 	 	=	-f -v
EXTENSION 	 	=	elf
DEBUG_LINUX 	= 

MAKE_NAME	 = linux.mk

include general.mk
