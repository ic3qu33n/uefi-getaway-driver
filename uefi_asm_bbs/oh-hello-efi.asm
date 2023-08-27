format pe64 efi
entry main

section '.text' code executable readable

;;include 'uefi.inc'


;; using FASM and UEFI.inc for generating tiny lil UEFI apps
;; This program references the tutorial on UEFI.inc page of OSDEV Wiki 
;; please refer to that resource for additional examples + more detailed walkthrough:
;; https://wiki.osdev.org/Uefi.inc

main:
;;	InitializeLib
;	jc @f

	; For the asm below I am referencing the excellent tutorial on johndk's website:
	; https://johv.dk/blog/bare-metal-assembly-tutorial
	;
	; The above guide gave me the foundation for building up the UEFI-specific asm routines
	; ty to jonas hvid for the excellent blog post!
	;
	; My additional notes are below:
	; SystemTable->ConOut->Outputstring(ConOut, _ohhello)
	; SystemTable will be in rdx on program invocation
	; offset of ConOut in SystemTable is 64, or 0x40, bytes
	; mov rcx, [rdx + 0x40]
	;offset of OutputString in EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL struct is 0x8
	; ConOut is of this type, so to get address of OutputString func
	; we just compute rcx (SystemTable->ConOut) + 8 (offset of OutputString func)
	; mov rax, [rcx + 8]
	; now rax contains address of func we want to call
	; rcx contains address of first parameter
	; we just need to load the address of our output string to the second param
	; mov rdx, _ohhello
	; okay cute, so all together now:
	
	mov rcx, [rdx + 0x40]
	mov rax, [rcx + 8]
	mov rdx, _ohhello

	sub rsp, 32
	call rax
	add rsp, 32

	; if we include uefi.inc then our binary grows to nearly 2600 bytes
	; this would be fun if it were 2600, but not very beneficial for golfin'
	; so we leave this out and explore writing our UEFI app in asm
	;uefi_call_wrapper ConOut, OutputString, ConOut, _ohhello
	ret
;@@: mov eax, EFI_SUCCESS
;	retn

section '.data' data readable writeable
_ohhello								du 'oh hello again', 13, 10 ,0

