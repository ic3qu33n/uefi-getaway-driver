BITS 64

default rel

section .header;
; ***References***
;
;	The following UEFI executable is made possible thanks to the work of the following:
;
; [1] windows golfclub examples, netspooky
;
; "tiny268_64.asm"
; from golfclub repo, windows folder
; by netspooky
; https://github.com/netspooky/golfclub/blob/master/windows/tiny268_64.asm
; 
;	and
;
; "ns.bggp2021.asm"" 
; from golfclub repo, windows folder
; by netspooky
; https://github.com/netspooky/golfclub/blob/master/windows/ns.bggp2021.asm	
;	
; [2] PE101 - corkami
; "PE 101 -  a windows executable walkthrough"
; corkami [Ange Albertini]
; https://github.com/corkami/pics/tree/master/binary/pe101
;
; [3] A Handmade Executable File, Big Mess O' Wires
; "A Handmade Executable File," by Steve
; Big Mess O' Wires, October 8, 2015
; https://www.bigmessowires.com/2015/10/08/a-handmade-executable-file/
;
; [4] "nasm-uefi" by Brian Otto
; https://github.com/BrianOtto/nasm-uefi/tree/master
;	
; [5] "nasm-uefi" by charlesap 
; https://github.com/charlesap/nasm-uefi/tree/master
;
; 
; ***********************
;	Notes
; ***********************
;
; From the "PE" article on OSDev Wiki:
; https://wiki.osdev.org/PE
; 
;
;struct PeHeader {
;	uint32_t mMagic; // PE\0\0 or 0x00004550
;	uint16_t mMachine;
;	uint16_t mNumberOfSections;
;	uint32_t mTimeDateStamp;
;	uint32_t mPointerToSymbolTable;
;	uint32_t mNumberOfSymbols;
;	uint16_t mSizeOfOptionalHeader;
;	uint16_t mCharacteristics;
;};
;
;// 1 byte aligned
;struct Pe32OptionalHeader {
;	uint16_t mMagic; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
;	uint8_t  mMajorLinkerVersion;
;	uint8_t  mMinorLinkerVersion;
;	uint32_t mSizeOfCode;
;	uint32_t mSizeOfInitializedData;
;	uint32_t mSizeOfUninitializedData;
;	uint32_t mAddressOfEntryPoint;
;	uint32_t mBaseOfCode;
;	uint32_t mBaseOfData;
;	uint32_t mImageBase;
;	uint32_t mSectionAlignment;
;	uint32_t mFileAlignment;
;	uint16_t mMajorOperatingSystemVersion;
;	uint16_t mMinorOperatingSystemVersion;
;	uint16_t mMajorImageVersion;
;	uint16_t mMinorImageVersion;
;	uint16_t mMajorSubsystemVersion;
;	uint16_t mMinorSubsystemVersion;
;	uint32_t mWin32VersionValue;
;	uint32_t mSizeOfImage;
;	uint32_t mSizeOfHeaders;
;	uint32_t mCheckSum;
;	uint16_t mSubsystem;
;	uint16_t mDllCharacteristics;
;	uint32_t mSizeOfStackReserve;
;	uint32_t mSizeOfStackCommit;
;	uint32_t mSizeOfHeapReserve;
;	uint32_t mSizeOfHeapCommit;
;	uint32_t mLoaderFlags;
;	uint32_t mNumberOfRvaAndSizes;
;};

START:
PE:
header_start:
mzheader:
	dw "MZ" 		;  DOS e_magic
	dw 0x100
;	dw 0x1		 	;  DOS e_cp
;	dw 0x0			;  DOS e_crlc
;	dw 0x4			;  DOS e_cparhdr
;	dw 0x10			;  DOS e_minalloc
;	dd 0xffff 		;  DOS e_maxalloc
;;
;	dw 0 			;  DOS e_ss
;	dw 0x140		;  DOS e_sp
;	dw 0			;  DOS e_csum
;	dw 0			;  DOS e_ip
;	dw 0			;  DOS e_cs
;	dw 0x40			;  DOS e_lfarlc
;	times 62-($-$$) db 0
;	dw 0x40
;
; MZ header re
; using the output vals from pe-parse to reconstruct  valid header for an efi bin
;
;  DOS e_magic
;  DOS e_cp
;  DOS e_crlc
;  DOS e_cparhdr
;  DOS e_minalloc
;  DOS e_maxalloc
;  DOS e_ss
;  DOS e_sp
;  DOS e_csum
;  DOS e_ip
;  DOS e_cs
;  DOS e_lfarlc
;
;


pe_header:
	dd "PE"			;	uint32_t mMagic; // PE\0\0 or 0x00004550
	dw 0x8664		;	uint16_t mMachine;
;
;	;times 14 db 0
;
	dw 3			;	uint16_t mNumberOfSections;
	dd 0x0 			;	uint32_t mTimeDateStamp;
	dd 0x0			;	uint32_t mPointerToSymbolTable;
	dd 0x0			;	uint32_t mNumberOfSymbols;

	dw sectionHeader - opt_header	 		;	uint16_t mSizeOfOptionalHeader;
	dw 0x0206 		;	uint16_t mCharacteristics;
opt_header:
	dw 0x20B		;	uint16_t mMagic; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
;
;	times 12 db 0

	db 0				;	uint8_t  mMajorLinkerVersion;
	db 0				;	uint8_t  mMinorLinkerVersion;
;	dd 0x100				;	uint32_t mSizeOfCode;
	dd _codeend - codestart			;	uint32_t mSizeOfCode;
	dd _dataend - _datastart	;	uint32_t mSizeOfInitializedData;
	dd 0				;	uint32_t mSizeOfUninitializedData;

					
	dd entrypoint - START		;	uint32_t mAddressOfEntryPoint;
;	dd 0x3000		;	uint32_t mAddressOfEntryPoint;
	;dd 0x1000		;	uint32_t mAddressOfEntryPoint;
	;dd _start - START		;	uint32_t mAddressOfEntryPoint;

;	times 10 db 0
;
	;dd 0x1000		;	uint32_t mBaseOfCode;
	dd entrypoint - START		;	uint32_t mBaseOfCode;
;	dd 0x3000		;	uint32_t mBaseOfCode;
;	dd _start - START		;	uint32_t mBaseOfCode;

	dq 0x0		;	uint32_t mImageBase;
	dd 0x4		;	uint32_t mSectionAlignment;
	dd 0x4		;	uint32_t mFileAlignment;

;	times 8 db 0
;	[this might be an incorrect placement of 8 null bytes so tbd on deleting this one]
	dw 0			;	uint16_t mMajorOperatingSystemVersion;
	dw 0			;	uint16_t mMinorOperatingSystemVersion;
	dw 0 			;	uint16_t mMajorImageVersion;
	dw 0			;	uint16_t mMinorImageVersion;

	dw 0			;	uint16_t mMajorSubsystemVersion;
	dw 0			;	uint16_t mMinorSubsystemVersion;  can be blank, still times 4 db 0
	dd 0			;	uint32_t mWin32VersionValue;

	;dd 0xf000  		;	uint32_t mSizeOfImage;
	;dd 0x3000  		;	uint32_t mSizeOfImage;
	dd end - START  		;	uint32_t mSizeOfImage;
	dd header_end - header_start			;	uint32_t mSizeOfHeaders;
	;times 4 db 0
	dd 0			;	uint32_t mCheckSum;
	dw 0xa			;	uint16_t mSubsystem;
	dw 0x0			;	uint16_t mDllCharacteristics;
	dq 0x0			;	uint32_t mSizeOfStackReserve;
	dq 0x0			;	uint32_t mSizeOfStackCommit;
	dq 0x0			;	uint32_t mSizeOfHeapReserve;
;	times 22 db 0
;	[this might be an incorrect placement of 8 null bytes so tbd on deleting this one]
	dq 0x0			;	uint32_t mSizeOfHeapCommit;
	dd 0x0			;	uint32_t mLoaderFlags;
	dd 0x6			;	uint32_t mNumberOfRvaAndSizes;
datadirs:
	dq 0	
	dq 0	
	dq 0	
	dq 0	
	dq 0	
	dq 0	
	;times 32 db 0
	;times 112 db 0
optend:

SECTS:
sectionHeader:					;struct IMAGE_SECTION_HEADER { // size 40 bytes
	db ".text",0,0,0			;	char[8]  mName;
	dd _codeend - codestart		 	;	uint32_t mVirtualSize;
	dd _start - START			;	uint32_t mVirtualAddress;
	dd _codeend - codestart			;	uint32_t mSizeOfRawData;
	dd _start - START			;	uint32_t mPointerToRawData;
	dd 0						;	uint32_t mPointerToRelocations;
	dd 0						;	uint32_t mPointerToLinenumbers;
	dw 0						;	uint16_t mNumberOfRelocations;
	dw 0						;	uint16_t mNumberOfLinenumbers;
	dd 0x60500020				;	uint32_t mCharacteristics;
								;};
dataSectionHeader:					;struct IMAGE_SECTION_HEADER { // size 40 bytes
	db ".data",0,0,0			;	char[8]  mName;
	dd _dataend - _datastart		 	;	uint32_t mVirtualSize;
	dd _datastart - START				;	uint32_t mVirtualAddress;
	dd _dataend - _datastart			;	uint32_t mSizeOfRawData;
	dd _datastart - START					;	uint32_t mPointerToRawData;
	dd 0						;	uint32_t mPointerToRelocations;
	dd 0						;	uint32_t mPointerToLinenumbers;
	dw 0						;	uint16_t mNumberOfRelocations;
	dw 0						;	uint16_t mNumberOfLinenumbers;
	dd 0xD0000040				;	uint32_t mCharacteristics;
								;};
relocSectionHeader:					;struct IMAGE_SECTION_HEADER { // size 40 bytes
	db ".reloc",0,0,0			;	char[8]  mName;
	dd 0		 				;	uint32_t mVirtualSize;
	dd 0						;	uint32_t mVirtualAddress;
	dd 0						;	uint32_t mSizeOfRawData;
	dd 0						;	uint32_t mPointerToRawData;
	dd 0						;	uint32_t mPointerToRelocations;
	dd 0						;	uint32_t mPointerToLinenumbers;
	dw 0						;	uint16_t mNumberOfRelocations;
	dw 0						;	uint16_t mNumberOfLinenumbers;
	dd 0x00000000				;	uint32_t mCharacteristics;
								;};
;	align 8
	times 512-($-$$) db 0
header_end:	
	
section .text follows=.header

global _start

codestart:
	
	EFI_BOOTSERVICES_ALLOCATEPOOL_OFFSET 			equ 0x40
	EFI_BOOTSERVICES_FREEPOOL_OFFSET 				equ 0x48
	EFI_BOOTSERVICES_HANDLEPROTOCOL_OFFSET 			equ 0x98
	EFI_BOOTSERVICES_OPENPROTOCOL_OFFSET 			equ 0x118

	
	EFI_LOADED_IMAGE_PROTOCOL_DEVICEHANDLE_OFFSET 	equ 0x18
	EFI_LOADED_IMAGE_PROTOCOL_FILEPATH_OFFSET		equ 0x20
	EFI_LOADED_IMAGE_PROTOCOL_IMAGESIZE_OFFSET		equ 0x48

	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPENVOLUME_OFFSET		equ 0x8

	EFI_FILE_PROTOCOL_OPEN_FILE_OFFSET				equ 0x8	
	EFI_FILE_PROTOCOL_CLOSE_FILE_OFFSET				equ 0x10	
	EFI_FILE_PROTOCOL_READ_FILE_OFFSET				equ 0x20
	EFI_FILE_PROTOCOL_WRITE_FILE_OFFSET				equ 0x28
	
	EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL equ  0x00000001

;/*
;	%macro UINTN 0
;		RESQ 1
;		alignb 8
;	%endmacro
;
;	%macro UINT32 0
;		RESD 1
;		alignb 4
;	%endmacro
;
;	%macro UINT64 0
;		RESQ 1
;		alignb 8
;	%endmacro
;
;	%macro EFI_HANDLE 0
;		RESQ 1
;		alignb 8
;	%endmacro
;
;	%macro POINTER 0
;		RESQ 1
;		alignb 8
;	%endmacro
;*/

;
; 		 From: https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#simple-file-system-protocol
;
;		 typedef struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {
;		  UINT64                                         Revision;
;		  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME    OpenVolume;
;		 } EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;
;

;
;		 typedef
;		 EFI_STATUS
;		 (EFIAPI *EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME) (
;		   IN EFI_SIMPLE_FILE_SYSTEM PROTOCOL                   *This,
;		   OUT EFI_FILE_PROTOCOL                                **Root
;		   );
;		 typedef struct_EFI_FILE_PROTOCOL {
;		   UINT64                          Revision;
;		   EFI_FILE_OPEN                   Open;
;		   EFI_FILE_CLOSE                  Close;
;		   EFI_FILE_DELETE                 Delete;
;		   EFI_FILE_READ                   Read;
;		   EFI_FILE_WRITE                  Write;
;		   EFI_FILE_GET_POSITION           GetPosition;
;		   EFI_FILE_SET_POSITION           SetPosition;
;		   EFI_FILE_GET_INFO               GetInfo;
;		   EFI_FILE_SET_INFO               SetInfo;
;		   EFI_FILE_FLUSH                  Flush;
;		   EFI_FILE_OPEN_EX                OpenEx; // Added for revision 2
;		   EFI_FILE_READ_EX                ReadEx; // Added for revision 2
;		   EFI_FILE_WRITE_EX               WriteEx; // Added for revision 2
;		   EFI_FILE_FLUSH_EX               FlushEx; // Added for revision 2
;		 } EFI_FILE_PROTOCOL;
;
;		EFI_ALLOCATE_TYPE definitions for Boot Services->AllocatePool() call
;		from Chapter 7 of UEFI spec: 
;		https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html#efi-boot-services-allocatepages
;
;		 //******************************************************
;		 //EFI_ALLOCATE_TYPE
;		 //******************************************************
;		 // These types are discussed in the "Description" section below.
;		 typedef enum {
;			AllocateAnyPages,
;			AllocateMaxAddress,
;			AllocateAddress,
;			MaxAllocateType
;		 } EFI_ALLOCATE_TYPE;
;		 
;		 //******************************************************
;		 //EFI_MEMORY_TYPE
;		 //******************************************************
;		 // These type values are discussed in Memory Type Usage before ExitBootServices()  and  Memory Type Usage after ExitBootServices().
;		 typedef enum {
;			EfiReservedMemoryType,
;			EfiLoaderCode,
;			EfiLoaderData,
;			EfiBootServicesCode,
;			EfiBootServicesData,
;			EfiRuntimeServicesCode,
;			EfiRuntimeServicesData,
;			EfiConventionalMemory,
;			EfiUnusableMemory,
;			EfiACPIReclaimMemory,
;			EfiACPIMemoryNVS,
;			EfiMemoryMappedIO,
;			EfiMemoryMappedIOPortSpace,
;			EfiPalCode,
;			EfiPersistentMemory,
;			EfiUnacceptedMemoryType,
;			EfiMaxMemoryType
;		 } EFI_MEMORY_TYPE;
;		 
;		 //******************************************************
;		 //EFI_PHYSICAL_ADDRESS
;		 //******************************************************
;		 typedef UINT64 EFI_PHYSICAL_ADDRESS;


_start:
entrypoint:
	push rbp
	mov rbp, rsp
	sub rsp,0xc0
	
	mov [ImageHandle], rcx
	mov [gST], rdx
	
	mov rbx, [gST]
	mov rbx, [rbx + 0x60]
	mov [gBS], rbx
	mov rax, [gST]
	mov rax, [rax + 0x40]
	mov [ConOut], rax

	mov rbx, [gBS]
	mov rdi, [rbx + 0x98]		;gBS->HandleProtocol()
	;mov rax, [rbx + 0x118]		;gBS->OpenProtocol()
								; params passed in rcx, rdx, r8, r9, r10
	mov rcx, [ImageHandle]

;	mov rdx, EFI_LOADED_IMAGE_PROTOCOL_GUID
	;;this is how we're passing the GUID so that it works	
	lea r8, [LoadedImageProtocol]
	mov dword [rbp-0x40], 0x5b1b31a1
	mov word [rbp-0x3c], 0x9562
	mov word [rbp-0x3a], 0x11d2
	mov rax, 0x3b7269c9a0003f8e
	mov [rbp-0x38], rax
	lea rdx, [rbp-0x40]
	mov r9, [ImageHandle]
	xor r10, r10
	mov rbx, EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL
	push rbx
	call rdi
	pop rbx
	mov [rbp-0x8], rax						;weird workaround so that rax is compared
	cmp qword [rbp -0x8], byte 0x0			;with the correct value for this check
	jne printerror



success_print:
	lea r13, HandleProtocolCheck
	call print

	mov rax, [LoadedImageProtocol]
	mov rbx, [rax + EFI_LOADED_IMAGE_PROTOCOL_DEVICEHANDLE_OFFSET]
	mov [DeviceHandle], rbx
	mov rax, [LoadedImageProtocol]
	mov rbx, [rax + EFI_LOADED_IMAGE_PROTOCOL_IMAGESIZE_OFFSET]
	mov [ImageSize], rbx
	jmp get_sfsp

printerror:
	lea r13, errormsg
	call print
	jmp exit

print:										;Print function
	mov rdx, r13
	mov rcx, [ConOut]
	mov rax, [rcx+0x8]				
	call rax
	ret

get_sfsp:
	mov rbx, [gBS]
	;mov rax, [rbx + 0x98]		;gBS->HandleProtocol()
	;mov rax, [rbx + 0x118]		;gBS->OpenProtocol()

							; params passed in rcx, rdx, r8, r9, r10
	mov rcx, [DeviceHandle]

	;lea rdx, [EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID]
	;;this is how we're passing the GUID so that it works	
	mov dword [rbp-0x60],0x964e5b22,
	mov word [rbp-0x5c], 0x6459,
	mov word [rbp-0x5a], 0x11d2
	mov rax, 0x3b7269c9a000398e
	mov [rbp-0x58], rax
	lea rdx, [rbp-0x60]

	lea r8, [SimpleFilesystemProtocol]
	mov r9, [ImageHandle]
	xor r10, r10
	mov rax, [rbx + 0x98]		;gBS->HandleProtocol()

	mov rbx, EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL
	push rbx
	call rax
	pop rbx
	mov [rbp-0x8], rax
	cmp qword [rbp -0x8], byte 0x0
	jne printerror
	lea r13, rootVolumeCheck
	call print

get_root_volume:
	mov rax, [SimpleFilesystemProtocol]
	mov rax, [rax + EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPENVOLUME_OFFSET]
	mov rcx, [SimpleFilesystemProtocol]	
	lea rdx, [root_volume]
	call rax
	mov [rbp-0x8], rax					;can probably move these 3 lines to a separate func
	cmp qword [rbp -0x8], byte 0x0		;error_check or something, since it's the same pattern
	jne printerror						;after return from each of these called functions

	lea r13, getrootvolumecheck			;I'd say same with these two lines, but the printing checks
	call print							;are just for debugging purposes during dev


open_hostfile:
	mov rax, [root_volume]
	mov rax, [rax + EFI_FILE_PROTOCOL_OPEN_FILE_OFFSET]
	mov rcx, [root_volume]	
	lea rdx, [hostfile]
	lea r8, hostfilename
	mov r9, [fileopen_mode] 
	mov r10, [hostattributes]
;	sub rsp, 8							;realign stack on 16byte boundary
	call rax
;	add rsp, 8
	mov [rbp-0x8], rax					;can probably move these 3 lines to a separate func
	cmp qword [rbp -0x8], byte 0x0		;error_check or something, since it's the same pattern
	jne printerror						;after return from each of these called functions

	lea r13, openhostfilecheck			;I'd say same with these two lines, but the printing checks
	call print							;are just for debugging purposes during dev


										;obv this is the same code as above w mods just for vars
open_targetfile:						;can/should be updated so that this function is abstracted 
	mov rax, [root_volume]				;to remove redundant code and minimize code size
	mov rax, [rax + EFI_FILE_PROTOCOL_OPEN_FILE_OFFSET]
	mov rcx, [root_volume]	
	mov qword [rbp - 0x78], 0x0
	lea rdx, [rbp-0x78]
	;mov rbx, [targetfile]
	;lea rdx, [targetfile]
	;lea rdx, [rbx]
	lea r8, targetfilename
	;mov r9, [targetfile_mode] 
	mov r9, 0x8000000000000003
	;mov qword r10, 0x0
	mov qword [rsp+0x20], 0x0
	;mov r10, [hostattributes]
;	sub rsp, 8							;realign stack on 16byte boundary
	call rax
;	add rsp, 8
	mov [rbp-0x8], rax					;can probably move these 3 lines to a separate func
	cmp qword [rbp -0x8], byte 0x0		;error_check or something, since it's the same pattern
	jne printerror						;after return from each of these called functions

	lea r13, opentargetfilecheck		;I'd say same with these two lines, but the printing checks
	call print							;are just for debugging purposes during dev
	
	mov rax, [rbp-0x78]
	mov [targetfile], rax







allocate_tmp_buffer:
	mov rax, [gBS]
	mov rax, [rax + EFI_BOOTSERVICES_ALLOCATEPOOL_OFFSET]
	mov rcx, [EFI_ALLOCATEPOOL_ALLOCATEANYPAGES]
	mov rdx, [ImageSize]
	lea r8, [temp_buffer]
	call rax
	mov [rbp-0x8], rax					;can probably move these 3 lines to a separate func
	cmp qword [rbp -0x8], byte 0x0		;error_check or something, since it's the same pattern
	jne printerror						;after return from each of these called functions

	lea r13, allocatepoolcheck			;I'd say same with these two lines, but the printing checks
	call print							;are just for debugging purposes during dev

read_hostfile:
	mov rax, [hostfile]
	mov rax, [rax + EFI_FILE_PROTOCOL_READ_FILE_OFFSET]
	mov rcx, [hostfile]
	lea rdx, [ImageSize]
	mov r8, [temp_buffer]
	
	call rax
	mov [rbp-0x8], rax					;can probably move these 3 lines to a separate func
	cmp qword [rbp -0x8], byte 0x0		;error_check or something, since it's the same pattern
	jne printerror						;after return from each of these called functions

	lea r13, readhostfilecheck			;I'd say same with these two lines, but the printing checks
	call print							;are just for debugging purposes during dev


	jmp baibai
	;jmp exit

baibai:
	jmp free_tmp_buffer	

close_file:
	mov rax, r13
	;mov rax, [hostfile]
	mov rax, [rax + EFI_FILE_PROTOCOL_CLOSE_FILE_OFFSET]
	;mov rcx, [hostfile]	
	mov rcx, r13
	call rax
	mov [rbp-0x8], rax					;can probably move these 3 lines to a separate func
	cmp qword [rbp -0x8], byte 0x0		;error_check or something, since it's the same pattern
	jne printerror						;after return from each of these called functions

	lea r13, closefilecheck				;I'd say same with these two lines, but the printing checks
	call print							;are just for debugging purposes during dev
	ret

	

free_tmp_buffer:
	mov rbx, [gBS]
	mov rax, [rbx + EFI_BOOTSERVICES_FREEPOOL_OFFSET]
	mov rcx, [temp_buffer]

	call rax
	mov [rbp-0x8], rax					;can probably move these 3 lines to a separate func
	cmp qword [rbp -0x8], byte 0x0		;error_check or something, since it's the same pattern
	jne printerror						;after return from each of these called functions

	lea r13, openhostfilecheck			;I'd say same with these two lines, but the printing checks
	call print							;are just for debugging purposes during dev
	
	mov r13, [hostfile]
	call close_file
	
	xor r13, r13
	mov r13, [root_volume]
	call close_file


exit:
	add rsp, 0xc0
	pop rbp
	ret
  
;; PE might require 28 bytes of paddiing here to conform to the f*d spec 
;; 28 bytes isn't even nicely aligned along a 16byte boundary so idfk
;	align 8
cEnd:
	;times 512-($-$$) db 0
_codeend:




section .data

_datastart:
	gST 					dq 0
	gBS 					dq 0
	ConOut 					dq 0
	ImageHandle 			dq 0
	LoadedImageProtocol		dq 0
	DeviceHandle			dq 0
	ImageSize 				dq 0
	root_volume				dq 0
;	efi_status				dq 0
	SimpleFilesystemProtocol 	dq 0
	hostfile				dq 0
	targetfile				dq 0
	hostattributes			dq 0x0
	fileopen_mode			dq 0x1
	targetfile_mode			dq 0x8000000000000003
	temp_buffer				dq 0

	EFI_SUCCESS				dq 0
	EFI_ALLOCATEPOOL_ALLOCATEANYPAGES	dq 0

	EFI_LOADED_IMAGE_PROTOCOL_GUID	dd 0x5b1b31a1, 
									dw 0x9562, 0x11d2
									db 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b

	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID 	dd 0x964e5b22,
											dw 0x6459, 0x11d2
											db 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b

	hostfilename 			db __utf16__ `\\self-rep-golf.efi\0`
	targetfilename 			db __utf16__ `4.efi\0`
	
	
;All the debug print strings 
	HandleProtocolCheck 	db __utf16__ `HandleProtocol call with ImageHandle successful \r\n\0`
	rootVolumeCheck 		db __utf16__ `Handle Protocol call for sfsp successful \r\n\0`
	getrootvolumecheck		db __utf16__ `get root volume with OpenVolume call successful\r\n\0` 
	openhostfilecheck		db __utf16__ `open hostfile with FILE_PROTOCOL Open call successful\r\n\0` 
	allocatepoolcheck		db __utf16__ `allocation for temp_buffer with gBS AllocatePool call successful\r\n\0` 
	freepoolcheck			db __utf16__ `free temp_buffer with gBS FreePool call successful\r\n\0` 
	readhostfilecheck		db __utf16__ `read hostfile with FILE_PROTOCOL Read call successful\r\n\0` 
	opentargetfilecheck		db __utf16__ `open targetfile with FILE_PROTOCOL Open call successful\r\n\0` 
	writetargetfilecheck	db __utf16__ `write targetfile with FILE_PROTOCOL Write call successful\r\n\0` 
	closefilecheck			db __utf16__ `close file with FILE_PROTOCOL Write call successful\r\n\0` 
	errormsg				db __utf16__ `uh ohhh EFI error \r\n\0`

	;times 512-($-$$) db 0
_dataend:	

section .reloc follows=.data
;empty but needed for UEFI for some reason?

end:
