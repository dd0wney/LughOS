#!/bin/bash
# filepath: /home/ddowney/Workspace/github.com/LughOS/scripts/test_x86.sh
# Simple script for running LughOS in QEMU without debugging

# Ensure the kernel exists
if [ ! -f build/x86/lughos.bin ]; then
    echo "Error: Kernel binary not found at build/x86/lughos.bin"
    echo "Please run 'make x86' first."
    exit 1
fi

# Start QEMU with proper flags for multiboot kernel
qemu-system-i386 \
    -kernel build/x86/lughos.bin \
    -initrd build/x86/user_hello \
    -nographic \
    -no-reboot \
    -monitor vc \
    -serial stdio \
    -serial file:/tmp/lugh_ipc.bin

echo "QEMU session ended."
