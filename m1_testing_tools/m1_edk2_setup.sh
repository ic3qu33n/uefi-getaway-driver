#!/bin/sh
brew install nasm
brew upgrade nasm
brew install acpica
brew upgrade acpica
brew install qemu
brew upgrade qemu

brew install x86_64-elf-binutils
brew install x86_64-elf-gcc
brew install x86_64-elf-gdb
brew install x86_64-linux-gnu-binutils

brew install mtoc

cd ~/uefi_testing
git clone https://github.com/tianocore/edk2.git
cd edk2
git submodule update --init

cd ~/uefi_testing
echo "export WORKSPACE=$(pwd)" >> ~/.zshrc

cd edk2
echo "export CONF_PATH=$(pwd)/Conf" >> ~/.zshrc
echo "export EDK2_TOOLS_PATH=$(pwd)/Conf" >> ~/.zshrc
echo "export UNIXGCC_X64_PETOOLS_PREFIX=/opt/homebrew/bin/x86_64-elf-" >> ~/.zshrc
echo "export GCC_X64_PREFIX=/opt/homebrew/bin/x86_64-elf-" >> ~/.zshrc
echo "export GCC_HOST_BIN=gcc" >> ~/.zshrc 
