#!/usr/bin/python3

import os
import sys
import re
#import gdb 
import subprocess

LOGFILE="debug.log"
TARGET_FILE="SmmCalloutDriver.efi"
TARGET="UEFI_bb_disk/"+TARGET_FILE
UEFI_DEBUG_PATTERN= r"Loading driver at (0x[0-9A-Fa-f]{8,}) EntryPoint=(0x[0-9A-Fa-f]{8,}) (\w+).efi"

def find_addresses(target_file: str):
	find_text_args=["objdump", TARGET, "-h"]
	find_offsets=subprocess.run(find_text_args, check=True, capture_output=True, encoding='utf-8').stdout
	#print(len(find_offsets))
	target_offsets=find_offsets.split('\n')
	for offset in target_offsets:
		if ".text" in offset:
			text_addr = offset.split()[2]
			print(f".text section address offset is: {text_addr}")
			print(f"text section offset is: {offset}")
		if ".data" in offset:
			data_addr = offset.split()[2]
			print(f".data section address offset is: {data_addr}")
			print(f"data section offset is: {offset}")
	if (text_addr is not None) and (data_addr is not None):
		return (text_addr, data_addr)
	return (None, None)

def find_drivers(target_file: str, log_file: str):
	with open(log_file, 'r') as f:
		log_data = f.read()
		driver_entry_points = re.finditer(UEFI_DEBUG_PATTERN, log_data)
		for elem in driver_entry_points:
			print(f"Driver entry point identified: {elem.group()}")
			if TARGET_FILE in elem.group():
					target_driver_base_address=elem.group(2)
					print(f"Target driver entry point identified: {elem.group()} \n Entry point is: {elem.group(2)} \n")
					return target_driver_base_address
	return 0

if __name__ == "__main__":
	target_base_addr=find_drivers(TARGET_FILE, LOGFILE)
	(text_addr, data_addr) = find_addresses(TARGET_FILE)
	print(f"Target driver base address is {target_base_addr} \n")
	print(f"Identified .text section address offset of target file is: {text_addr} \n")
	print(f"Identified .data section address offset of target file is: {data_addr} \n")
