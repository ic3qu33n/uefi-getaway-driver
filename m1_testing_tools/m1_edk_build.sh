#!/bin/bash

cd ~/uefi_testing/edk2
echo $(pwd)
build -a X64 -b DEBUG -t GCC -p OvmfPkg/OvmfPkgX64.dsc
