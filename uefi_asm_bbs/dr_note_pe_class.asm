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
; [4]
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
	dw 2			;	uint16_t mNumberOfSections;
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
	align 4
	;times 512-($-$$) db 0
;	times 512-($-START) db 0
header_end:	
	
section .text follows=.header

global _start

codestart:	
	EFI_BOOTSERVICES_ALLOCATEPOOL_OFFSET 		equ 0x40
	EFI_BOOTSERVICES_HANDLEPROTOCOL_OFFSET 		equ 0x98
	EFI_LOADED_IMAGE_PROTOCOL_GUID		db  0x5B, 0x1B, 0x31, 0xA1, 0x95, 0x62, 0x11, 0xd2 
										db 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B

	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID 	db 0x96, 0x4e, 0x5b, 0x22,0x64,0x59,0x11,0xd2
										db 0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b

_start:
entrypoint:
;	align 4
;	mov [SystemTable], rdx
;	mov rcx, [SystemTable]
;	mov rcx, [rcx + 0x40]
;	;mov rcx, qword [rdx+0x40] 	;SystemTable in rdx upon efi program invovation
;	mov rax, rcx
;	;mov rax, qword [rax+0x8]				;
;	mov rax, [rax + 0x8]
;	lea rdx, [_ohhello]
;	sub rsp, 32
;	call rax
;	add rsp, 32
;	ret
	



	mov [ImageHandle], rcx
	mov [gST], rdx

	push rbp
	mov rsp, rbp
	sub rsp, 32
	lea rbx, [rdx + 0x60]
	mov [gBS], rbx
	
	mov rbx, [gST]
	mov rbx, [rbx + 0x60]
	mov [gBS], rbx
	mov rax, [gST]
	mov rax, [rax + 0x40]
	mov [ConOut], rax

	mov rbx, [gBS]
	mov rax, [rbx + 0x98]		;gBS->HandleProtocol()

							; params passed in rcx, rdx, r8, r9, r10
	mov rcx, [ImageHandle]
	mov rdx, EFI_LOADED_IMAGE_PROTOCOL_GUID
	lea r8, [LoadedImageProtocol]

	call rax
	add rsp, 32
	pop rbp
	ret                       ; Get outta there
  
;	_ohhello:	db __utf16__ 'oh hello there', 13, 10, 0
;; required 28 bytes of paddiing to conform to the f*d spec 
;; 28 bytes isn't even nicely aligned along a 16byte boundary so idfk
;dq 0x9090909090909090 ;; bootleg padding
;  dq 0x909090 ;; bootleg padding
	align 4
	;  db 0x48, 0xBF, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x00, 0x00, 0xFF, 0xD7 ; only use if you need to crash the monitor
cEnd:
	;padding:
	;	times 64-($-_start) db 90
	;	times 272-($-mzheader) db 90
	;times 1024-($-$$) db 0
_codeend:

section .reloc
;empty but needed for UEFI for some reason?



;.data
section .data

_datastart:
	;_ohhello:	db __utf16__ 'oh hello there', 13, 10, 0
	_ohhello			db __utf16__ 'oh hello there\r\n\0'
;	SystemTable  		dq 0
;	BootServicesTable  	dq 0

	gST 					dq 0
	gBS 					dq 0
	ConOut 					dq 0
	ImageHandle 			dq 0
	LoadedImageProtocolGuid	equ EFI_LOADED_IMAGE_PROTOCOL_GUID
	LoadedImageProtocol		dq 0
	DeviceHandle			dq 0
	FilePath				dq 0
	ImageSize 				dq 0

	;times 512-($-$$) db 0
	align 4
_dataend:	
end:
