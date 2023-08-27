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
	dw "MZ"
	dw 0x100
pe_header:
	dd "PE"			;	uint32_t mMagic; // PE\0\0 or 0x00004550
	dw 0x14C		;	uint16_t mMachine;
	times 14 db 0
	db 0			;	uint16_t mNumberOfSections;
	db 0 			;	uint16_t mSizeOfOptionalHeader;
	dw 0x103 			;	uint16_t mCharacteristics;
opt_header:
	dw 0x20B		;	uint16_t mMagic; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
	times 12 db 0
	dd start - $$		;	uint32_t mAddressOfEntryPoint;
	times 10 db 0
	dd 0x400000		;	uint32_t mImageBase;
	dd 4			;	uint32_t mSectionAlignment;
	dd 4			;	uint32_t mFileAlignment;
	times 8 db 0
	dw 5			;	uint16_t mMajorSubsystemVersion;
	times 7 db 0
	dd 0x2000  		;	uint32_t mSizeOfImage;
	dd  0			;	uint32_t mSizeOfHeaders;
	times 3 db 0
	dw 3			;	uint16_t mSubsystem;
	times 22 db 0
	dd 14			;	uint32_t mNumberOfRvaAndSizes;
datadirs:
	times 56 db 0

_ohhello:	db __utf16__ 'oh hello there', 13, 10, 0	
		
start:
	mov rcx, [rdx + 0x40] 	;SystemTable in rdx upon efi program invovation
	mov rax, [rcx + 0x8]				;
	mov rdx, _ohhello
	sub rsp, 32
	call rax
	add rsp, 32
	ret

