#!/bin/bash
# Check whether the LughOS cross-toolchains are present.
#
# stdout:  <NAME>_TOOLCHAIN_AVAILABLE=0|1 — one line per arch.
#          Consumed by the top-level Makefile via $(shell ...) — must stay stable.
#
# stderr:  Install hints for missing toolchains, gated on `[ -t 1 ]` so that
#          $(shell) captures from make (stdout is a pipe, not a TTY) stay silent.
#          Running the script interactively (`./scripts/check_toolchains.sh`)
#          shows the hints; running it under make does not.

set -u

OS="$(uname -s)"
MISSING=()

check_one() {
    local var="$1" cmd="$2" opt_dir="$3"
    if command -v "$cmd" >/dev/null 2>&1 || [ -d "$opt_dir" ]; then
        echo "${var}=1"
    else
        echo "${var}=0"
        MISSING+=("$var")
    fi
}

check_one X86_TOOLCHAIN_AVAILABLE   i686-elf-gcc          /opt/i686-elf
check_one RISCV_TOOLCHAIN_AVAILABLE riscv64-linux-gnu-gcc /opt/riscv64-linux-gnu
check_one ARM_TOOLCHAIN_AVAILABLE   arm-none-eabi-gcc     /opt/arm-none-eabi

# No hints needed if everything is present, or if stdout is piped (make).
[ ${#MISSING[@]} -eq 0 ] && exit 0
[ -t 1 ] || exit 0

hint() { >&2 echo "$1"; }

hint ""
hint "Missing toolchains: ${MISSING[*]}"

case "$OS" in
    Darwin)
        hint ""
        hint "Install on macOS (Homebrew):"
        for m in "${MISSING[@]}"; do
            case "$m" in
                X86_TOOLCHAIN_AVAILABLE)
                    hint "  x86   : brew tap nativeos/i686-elf-toolchain"
                    hint "          brew install i686-elf-binutils i686-elf-gcc"
                    ;;
                ARM_TOOLCHAIN_AVAILABLE)
                    hint "  arm   : brew install --cask gcc-arm-embedded"
                    ;;
                RISCV_TOOLCHAIN_AVAILABLE)
                    hint "  riscv : brew tap riscv-software-src/riscv"
                    hint "          brew install riscv-gnu-toolchain"
                    hint "          (Mac binary may install as riscv64-unknown-elf-gcc;"
                    hint "           symlink to riscv64-linux-gnu-gcc or adjust the Makefile.)"
                    ;;
            esac
        done
        ;;
    Linux)
        if command -v dnf >/dev/null 2>&1; then
            hint ""
            hint "Install on Fedora (dnf):"
            for m in "${MISSING[@]}"; do
                case "$m" in
                    X86_TOOLCHAIN_AVAILABLE)
                        hint "  x86   : build from source — https://wiki.osdev.org/GCC_Cross-Compiler"
                        ;;
                    ARM_TOOLCHAIN_AVAILABLE)
                        hint "  arm   : sudo dnf install -y gcc-arm-none-eabi binutils-arm-none-eabi"
                        ;;
                    RISCV_TOOLCHAIN_AVAILABLE)
                        hint "  riscv : sudo dnf install -y gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu"
                        ;;
                esac
            done
        elif command -v apt-get >/dev/null 2>&1; then
            hint ""
            hint "Install on Debian/Ubuntu (apt):"
            for m in "${MISSING[@]}"; do
                case "$m" in
                    X86_TOOLCHAIN_AVAILABLE)
                        hint "  x86   : build from source — https://wiki.osdev.org/GCC_Cross-Compiler"
                        ;;
                    ARM_TOOLCHAIN_AVAILABLE)
                        hint "  arm   : sudo apt install -y gcc-arm-none-eabi binutils-arm-none-eabi"
                        ;;
                    RISCV_TOOLCHAIN_AVAILABLE)
                        hint "  riscv : sudo apt install -y gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu"
                        ;;
                esac
            done
        fi
        ;;
esac

# Hint about QEMU only if it's also missing — most contributors already have it.
if ! command -v qemu-system-i386 >/dev/null 2>&1; then
    hint ""
    hint "QEMU is also required to run the kernel:"
    case "$OS" in
        Darwin) hint "  brew install qemu";;
        Linux)  hint "  sudo dnf install -y qemu-system-x86 qemu-system-arm qemu-system-riscv  # Fedora";;
    esac
fi

hint ""
