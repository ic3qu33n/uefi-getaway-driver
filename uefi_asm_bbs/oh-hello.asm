format pe64 dll efi
entry main

section ',text' code executable

include 'uefi.inc'


;; using FASM and UEFI.inc for generating tiny lil UEFI apps
;; This program references the tutorial on UEFI.inc page of OSDEV Wiki 
;; please refer to that resource for additional examples + more detailed walkthrough:
;; https://wiki.osdev.org/Uefi.inc

main:
	InitializeLib
	jc @f
	uefi_call_wrapper ConOut, OutputString, ConOut, _hello

@@: mov eax, EFI_SUCCESS
	retn

section '.data' data readable writeable
_ohhello								du 'oh hello again', 13, 10 ,0


