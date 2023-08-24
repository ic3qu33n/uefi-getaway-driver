#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

EFI_STATUS
EFIAPI
UefiMain (
	IN EFI_HANDLE			ImageHandle,
	IN EFI_SYSTEM_TABLE		*SystemTable
	)

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
	//also see this part of the EDK2 reference code: https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Uefi/UefiSpec.h#L160

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
