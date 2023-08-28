bits 64
;
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


mzheader:
	dd "MZ" 		;  DOS e_magic
	dw 0x1		 	;  DOS e_cp
	dw 0x0			;  DOS e_crlc
	dw 0x4			;  DOS e_cparhdr
	dw 0x10			;  DOS e_minalloc
	dd 0xffff 		;  DOS e_maxalloc

	dw 0 			;  DOS e_ss
	dw 0x140		;  DOS e_sp
	dw 0			;  DOS e_csum
	dw 0			;  DOS e_ip
	dw 0			;  DOS e_cs
	dw 0x40			;  DOS e_lfarlc
	times 62-($-$$) db 0
	dw 0x40
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
	dw 1			;	uint16_t mNumberOfSections;
	dd 0x0 			;	uint32_t mTimeDateStamp;
	dd 0x0			;	uint32_t mPointerToSymbolTable;
	dd 0x0			;	uint32_t mNumberOfSymbols;

	dw 0xf0 		;	uint16_t mSizeOfOptionalHeader;
	dw 0x2f 		;	uint16_t mCharacteristics;
opt_header:
	dw 0x20B		;	uint16_t mMagic; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
;
;	times 12 db 0

	db 1				;	uint8_t  mMajorLinkerVersion;
	db 73				;	uint8_t  mMinorLinkerVersion;
	dd 0				;	uint32_t mSizeOfCode;
	dd 0				;	uint32_t mSizeOfInitializedData;
	dd 0				;	uint32_t mSizeOfUninitializedData;

					
	dd $_start		;	uint32_t mAddressOfEntryPoint;

;	times 10 db 0
;
	dd 0			;	uint32_t mBaseOfCode;

	dd 0x400000		;	uint32_t mImageBase;
	dd 0x1000		;	uint32_t mSectionAlignment;
	dd 0x200		;	uint32_t mFileAlignment;

;	times 8 db 0
;	[this might be an incorrect placement of 8 null bytes so tbd on deleting this one]

	dw 1			;	uint16_t mMajorSubsystemVersion;
	dw 0			;	uint16_t mMinorSubsystemVersion;  can be blank, still times 4 db 0
	dd 0			;	uint32_t mWin32VersionValue;

	dd 0x3000  		;	uint32_t mSizeOfImage;
	dd 0x200			;	uint32_t mSizeOfHeaders;
	times 4 db 0
	dw 0xa			;	uint16_t mSubsystem;
	dw 0x0			;	uint16_t mDllCharacteristics;
	dd 0x1000		;	uint32_t mSizeOfStackReserve;
	dd 0x1000		;	uint32_t mSizeOfStackCommit;
	dd 0x100000		;	uint32_t mSizeOfHeapReserve;
;	times 22 db 0
;	[this might be an incorrect placement of 8 null bytes so tbd on deleting this one]
	dd 0			;	uint32_t mSizeOfHeapCommit;
	dd 0			;	uint32_t mLoaderFlags;
	dd 16			;	uint32_t mNumberOfRvaAndSizes;
;datadirs:
	;times 32 db 0
	;times 112 db 0

_ohhello:	db __utf16__ 'oh hello there', 13, 10, 0	
		
_start:
	mov rcx, [rdx + 0x40] 	;SystemTable in rdx upon efi program invovation
	mov rax, [rcx + 0x8]				;
	mov rdx, $_ohhello
	sub rsp, 32
	call rax
	add rsp, 32
	retn

;; required 28 bytes of paddiing to conform to the f*d spec 
;; 28 bytes isn't even nicely aligned along a 16byte boundary so idfk
;;  

padding:
	times 268-($-$$) db 0
