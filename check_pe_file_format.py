#!/usr/bin/python3

import sys, os
import subprocess
import re
import pefile


########################################################################################
#	A simple Python script for copying EFI binaries built with EDK2 and OVMF
#   copying the resultant .efi binary to the target root disk for QEMU
#   and launching a qemu-system-x86_64 session for testing
#
#	There isn't anything *wild* or super interesting about this script
#	tbh I just didn't want to keep typing these really long qemu commands over and over
########################################################################################

workspace="$WORKSPACE"
edk2_dir= workspace + "edk2/"
uefi_asm_dir= workspace + "uefi_asm_bbs/"
#uefi_testingdir_cmd=["cd", edk2_dir, "&&", ". ./edksetup.sh"]

#uefi_app_build_cmd= ["build",  "--platform=BareBonesPkg/BareBonesPkg.dsc",  "--arch=X64", "--buildtarget=RELEASE", "--tagname=GCC"]

target_pkg="Build/BareBonesPkg/RELEASE_GCC/X64/"
uefi_app_name="dr-note-pe-class.efi"
baseline_uefi_app_name="oh-hello-efi.efi"
target_uefi_app= uefi_asm_dir + uefi_app_name
baseline_uefi_app= uefi_asm_dir + baseline_uefi_app_name

target_disk= workspace + "/UEFI_bb_disk"

uefi_copy_app_cmd=["cp", target_uefi_app, target_disk]

uefi_app_run_cmd=["/opt/homebrew/bin/qemu-system-x86_64", "-drive", "if=pflash,format=raw,file=edk2/Build/OvmfX64/RELEASE_GCC/FV/OVMF.fd", "-drive", "format=raw,file=fat:rw:UEFI_bb_disk", "-nographic","-net","none"]

uefi_app_run_debug_cmd=["/opt/homebrew/bin/qemu-system-x86_64", "-drive", "if=pflash,format=raw,file=/Users/nika/uefi_testing/edk2/Build/OvmfX64/DEBUG_GCC/FV/OVMF.fd", "-drive", "format=raw,file=fat:rw:UEFI_bb_disk", "-nographic","-net","none","-global","isa-debugcon.iobase=0x402","-debugcon","file:debug.log", "-s"]


if __name__ == '__main__':
	try:
	#	subprocess.run(uefi_copy_app_cmd)

		pe=pefile.PE(target_uefi_app)
		print(pe.dump_info())	
		
		#baseline_pe=pefile.PE(target_uefi_app)
		#print("*** Info about baseline file: \n\n")	
		#print(baseline_pe.dump_info())	
		
	
	except (RuntimeError, TypeError) as e:
		print("oh no. error error: {0}".format(e))
	
