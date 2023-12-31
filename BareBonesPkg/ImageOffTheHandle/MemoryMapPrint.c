#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

EFI_STATUS
EFIAPI
UefiMain (
	IN EFI_HANDLE			ImageHandle,
	IN EFI_SYSTEM_TABLE		*SystemTable
	)

// ****************************************************************************************
// References: 
// ****************************************************************************************
// This stackoverflow answer to the question "Can I write on my local filesystem using efi":
// https://stackoverflow.com/questions/32324109/can-i-write-on-my-local-filesystem-using-efi
//
//
//
//
// ****************************************************************************************
// Relevant struct definitions (and their corresponding URLs) from the UEFI spec are below:
// ****************************************************************************************
//
// EFI_LOADED_IMAGE_PROTOCOL struct:
//
// typedef struct {
//   UINT32                        Revision;
//   EFI_HANDLE                    ParentHandle;
//   EFI_System_Table              *SystemTable;
//
//   // Source location of the image
//   EFI_HANDLE                    DeviceHandle;
//   EFI_DEVICE_PATH_PROTOCOL      *FilePath;
//   VOID                          *Reserved;
//
//   // Image’s load options
//   UINT32                        LoadOptionsSize;
//   VOID                          *LoadOptions;
//
//   // Location where image was loaded
//   VOID                          *ImageBase;
//   UINT64                        ImageSize;
//   EFI_MEMORY_TYPE               ImageCodeType;
//   EFI_MEMORY_TYPE               ImageDataType;
//   EFI_IMAGE_UNLOAD              Unload;
//} EFI_LOADED_IMAGE_PROTOCOL;
//
//
// Two most relevant protocols here are 
// EFI_LOADED_IMAGE_PROTOCOL
// and
// EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL
// For more details, see overview here:
// https://uefi.org/specs/UEFI/2.10/09_Protocols_EFI_Loaded_Image.html
//
// also note that  EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL
// and EFI_DEVICE_PATH_PROTOCOL
// are the same, they just have diff GUIDs
//
// For details on EFI_DEVICE_PATH_PROTOCOL see:
//  https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#efi-device-path-protocol
// 
//	Protocol interface structure for EFI_DEVICE_PATH_PROTOCOL (from above link):
//******************************************************
// EFI_DEVICE_PATH_PROTOCOL
//******************************************************
//typedef struct _EFI_DEVICE_PATH_PROTOCOL {
//  UINT8           Type;
//  UINT8           SubType;
//  UINT8           Length[2];
// } EFI_DEVICE_PATH_PROTOCOL;
//
//
//
// EFI_LOADED_IMAGE_PROTOCOL -> DeviceHandle -> VolumeHandle
// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL -> OpenVolume

// From UEFI Spec:
// https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#efi-simple-file-system-protocol-openvolume
//
// typedef
//EFI_STATUS
//(EFIAPI *EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME) (
//  IN EFI_SIMPLE_FILE_SYSTEM PROTOCOL                   *This,
//  OUT EFI_FILE_PROTOCOL                                **Root
//  );
//
// Finally, use EFI_FILE_PROTOCOL->EFI_FILE_OPEN to creae a new file
// see  https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/SimpleFileSystem.h#L115
// EFI_FILE_OPEN prototype is below:
///**
//******************************************************
// EFI_FILE_OPEN
//******************************************************
//  Opens a new file relative to the source file's location.
//
//  @param  This       A pointer to the EFI_FILE_PROTOCOL instance that is the file
//                     handle to the source location. This would typically be an open
//                     handle to a directory.
//  @param  NewHandle  A pointer to the location to return the opened handle for the new
//                     file.
//  @param  FileName   The Null-terminated string of the name of the file to be opened.
//                     The file name may contain the following path modifiers: "\", ".",
//                     and "..".
//  @param  OpenMode   The mode to open the file. The only valid combinations that the
//                     file may be opened with are: Read, Read/Write, or Create/Read/Write.
//  @param  Attributes Only valid for EFI_FILE_MODE_CREATE, in which case these are the
//                     attribute bits for the newly created file.
//
//  @retval EFI_SUCCESS          The file was opened.
//  @retval EFI_NOT_FOUND        The specified file could not be found on the device.
//  @retval EFI_NO_MEDIA         The device has no medium.
//  @retval EFI_MEDIA_CHANGED    The device has a different medium in it or the medium is no
//                               longer supported.
//  @retval EFI_DEVICE_ERROR     The device reported an error.
//  @retval EFI_VOLUME_CORRUPTED The file system structures are corrupted.
//  @retval EFI_WRITE_PROTECTED  An attempt was made to create a file, or open a file for write
//                               when the media is write-protected.
//  @retval EFI_ACCESS_DENIED    The service denied access to the file.
//  @retval EFI_OUT_OF_RESOURCES Not enough resources were available to open the file.
//  @retval EFI_VOLUME_FULL      The volume is full.
//
//**/
//typedef
//EFI_STATUS
//(EFIAPI *EFI_FILE_OPEN)(
//  IN EFI_FILE_PROTOCOL        *This,
//  OUT EFI_FILE_PROTOCOL       **NewHandle,
//  IN CHAR16                   *FileName,
//  IN UINT64                   OpenMode,
//  IN UINT64                   Attributes
//  );
//
////
//// Open modes
////
//#define EFI_FILE_MODE_READ    0x0000000000000001ULL
//#define EFI_FILE_MODE_WRITE   0x0000000000000002ULL
//#define EFI_FILE_MODE_CREATE  0x8000000000000000ULL
//
////
//// File attributes
////
//#define EFI_FILE_READ_ONLY   0x0000000000000001ULL
//#define EFI_FILE_HIDDEN      0x0000000000000002ULL
//#define EFI_FILE_SYSTEM      0x0000000000000004ULL
//#define EFI_FILE_RESERVED    0x0000000000000008ULL
//#define EFI_FILE_DIRECTORY   0x0000000000000010ULL
//#define EFI_FILE_ARCHIVE     0x0000000000000020ULL
//#define EFI_FILE_VALID_ATTR  0x0000000000000037ULL
//
//
// 

EFI_LOADED_IMAGE_PROTOCOL loadedimage = NULL;
EFI_DEVICE_PATH_PROTOCOL devicepath = NULL;


{
	EFI_BOOT_SERVICES *gBS=(SystemTable->BootServices);
//	EFI_LOCATE_PROTOCOL locateProtocolHook=(gBS->LocateProtocol);
	UINTN MemoryMapSize = 0;
	EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
	UINTN MapKey;
	UINTN DescriptorSize;
	UINT32 DescriptorVersion;

	EFI_STATUS Mem_Status;
	//MemoryMap is an array of EFI_MEMORY_DESCRIPTORs
	//see detailed notes here: https://github.com/Kostr/UEFI-Lessons/tree/master/Lessons/Lesson_11
	//also see this part of the EDK2 reference code: 
	//https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Uefi/UefiSpec.h#L160

	//UEFI BootServices.GetMemoryMap() prototype:
	/*	typedef
	/	EFI_STATUS
	/	(EFIAPI \*EFI_GET_MEMORY_MAP) (
	/	   IN OUT UINTN                  *MemoryMapSize,
	/	   OUT EFI_MEMORY_DESCRIPTOR     *MemoryMap,
	/	   OUT UINTN                     *MapKey,
	/	   OUT UINTN                     *DescriptorSize,
	/	   OUT UINT32                    *DescriptorVersion
  	/	);
	/ from: https://uefi.org/specs/UEFI/2.9_A/07_Services_Boot_Services.html#efi-boot-services-getmemorymap
	*/
	
	//	And the relevant,related prototype for EFI_MEMORY_DESCRIPTOR:
	/*****************************************************/
	//EFI_MEMORY_DESCRIPTOR
	/******************************************************
	/typedef struct {
	/   UINT32                     Type;
	/   EFI_PHYSICAL_ADDRESS       PhysicalStart;
	/   EFI_VIRTUAL_ADDRESS        VirtualStart;
	/   UINT64                     NumberOfPages;
	/   UINT64                     Attribute;
	/  } EFI_MEMORY_DESCRIPTOR;
	/	/
	*/
	
	Mem_Status = gBS->GetMemoryMap(
		&MemoryMapSize,
		MemoryMap,
		&MapKey,
		&DescriptorSize,
		&DescriptorVersion
	);
	//This call populates MemoryMapSize with the correct size of the MemoryMap
	// to be used in the next call for allocating sufficient memory for the MemoryMap with AllocatePool()
	
	if (Mem_Status == EFI_BUFFER_TOO_SMALL){

		//EfiBootServicesData; 
		//default memory type used by uefi boot service's driver when allocating memory with AllocatePool()
		// see EfiMemoryTypes reference info here: https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Uefi/UefiMultiPhase.h
		Mem_Status = gBS->AllocatePool(
			EfiBootServicesData,
			MemoryMapSize,
			(void**)&MemoryMap); 
		
		// see this reference for uefi driver writer's guide to avoiding compiler warnings re: type checking:
		// https://github.com/tianocore-docs/edk2-UefiDriverWritersGuide/blob/master/4_general_driver_design_guidelines/41_common_coding_practices/411_type_checking.md
		// basically, we want this convention for avoiding a type confusion compiler warning: 
		// (void**) &MyStructure;
		// So typically we would do something like this:
		//	sizeof(MAPSTRUCT),
		//	(void**)&MAPSTRUCT); 
		if (! EFI_ERROR(Mem_Status)) {	
			Mem_Status = gBS->GetMemoryMap(
				&MemoryMapSize,
				MemoryMap,
				&MapKey,
				&DescriptorSize,
				&DescriptorVersion
			);
			//Virtual Size must be aligned on 4 kb boundary so address range for each EFI_MEMORY_DESCRIPTOR struct in the returned list
			// will be [PhysicalStart, PhysicalStart + numberOfPages * 4096 - 1]
			//so we can use this as our address range to print
			//this should be equal to DescriptorSize for each EFI_MEMORY_DESCRIPTOR ( which is a list of structs that we are traversing;
			//DescriptorSize corresponds to the head of the list with respect to our place in it, so DescriptorSize will update each time
			// and we can use that as the increment value of our address pointer;)
		EFI_MEMORY_DESCRIPTOR *efimemmap = MemoryMap;
		UINTN PAGESIZE = 4096;
		
		while (((UINT8*) efimemmap) < (UINT8*)MemoryMap + MemoryMapSize){
			UINTN efimmap_size = (UINTN) efimemmap->NumberOfPages * PAGESIZE;	
			//UINTN efimmap_type = (UINTN) efimemmap->Type;
			UINTN efimmap_adrstart = (UINTN) efimemmap->PhysicalStart;
			//UINTN efimmap_attrs = (UINTN) efimemmap->Attribute;
			
			Print(L"Identified Memory Map EFI_MEMORY_DESCRIPTOR address range: %016llx %016llx \n\n", efimmap_adrstart ,  efimmap_adrstart + efimmap_size);	
			//Print(L"Identified Memory Map EFI_MEMORY_DESCRIPTOR type: %s and attributes: %s \n\n", &efimmap_type ,  &efimmap_attrs);	
			efimemmap = (EFI_MEMORY_DESCRIPTOR*) (efimemmap + DescriptorSize);
		}
	}
	gBS->FreePool(MemoryMap);
	}

	//SystemTable->ConOut->OutputString(SystemTable->ConOut, L"hello from the other side\n");
	return Mem_Status;
}
//	Print(L"Boot Services Table address is: %p \n\n", &gBS);	
//	Print(L"Boot Services LocateHandleBuffer() function pointer  address is: %p \n\n", &locateProtocolHook);	
	//SystemTable->ConOut->OutputString(SystemTable->ConOut,L"%s", &bootservicestest);
//	/*for(int i=0; i < sizeof bootserviceaddress; i++){
//		SystemTable->ConOut->OutputString(SystemTable->ConOut, bst_adr[i]);
//	}*/
//}
