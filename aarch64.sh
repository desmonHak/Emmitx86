#!/bin/bash
set -e

# Dependencias
echo "[+] Instalando herramientas necesarias..."
sudo apt update || true
sudo apt install -y qemu-system-aarch64 qemu-utils wget parted

# Variables
ISO_URL="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/aarch64/alpine-standard-3.21.0-aarch64.iso"
ISO_IMG="alpine-standard-3.21.0-aarch64.iso"
ALPINE_IMG="alpine.img"
DATA_IMG="data.img"
BIN="examples/*.elf"



# Descargar ISO de Alpine
if [ ! -f "$ISO_IMG" ]; then
    echo "[+] Descargando ISO Alpine..."
    wget -O "$ISO_IMG" "$ISO_URL"
fi

# Crear imagen de disco para rootfs
if [ ! -f "$ALPINE_IMG" ]; then
    echo "[+] Creando imagen de Alpine..."
    qemu-img create -f raw "$ALPINE_IMG" 1G
fi

# Crear imagen de datos
if [ ! -f "$DATA_IMG" ]; then
    echo "[+] Creando imagen de datos..."
    qemu-img create -f raw "$DATA_IMG" 20M
    parted "$DATA_IMG" --script mklabel msdos
    parted "$DATA_IMG" --script mkpart primary ext4 1MiB 100%
    LOOP=$(sudo losetup --find --show --partscan "$DATA_IMG")
    sudo mkfs.ext4 "${LOOP}p1"
    sudo mkdir -p /mnt/data
    sudo mount "${LOOP}p1" /mnt/data
    sudo cp $BIN /mnt/data/
    sudo umount /mnt/data
    sudo losetup -d "$LOOP"
fi

sudo apt install qemu-efi-aarch64
# Usar el firmware instalado por el paquete qemu-efi-aarch64
BIOS="/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"

# Ejecutar QEMU con la ISO de Alpine
echo "[+] Iniciando QEMU con la ISO de Alpine..."
qemu-system-aarch64 \
    -machine virt \
    -cpu cortex-a57 \
    -m 1024 \
    -cdrom "$ISO_IMG" \
    -drive file="$ALPINE_IMG",format=raw,if=virtio \
    -drive file="$DATA_IMG",format=raw,if=virtio \
    -bios "$BIOS" \
    -serial stdio \
    -display sdl

# Una vez dentro de Alpine, puedes montar el disco de datos y ejecutar tu binario ARM:
# mkdir /mnt/data
# mount /dev/vdb1 /mnt/data
# /mnt/data/code_arm.elf
