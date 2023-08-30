#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/LoadedImage.h>
#include <Guid/FileInfo.h>


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
// This repo of example UEFI apps by PF-Maillard:
// https://github.com/PF-Maillard/UEFI_BMP_Application/tree/master
//	Specifically this file:
// https://github.com/PF-Maillard/UEFI_BMP_Application/blob/master/MyBmpApplication.c
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
// EFI_DEVICE_PATH_TO_TEXT_PROTOCOL.ConvertDevicePathToText()
// from UEFI spec, see reference:
// https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html?#efi-device-path-to-text-protocol-convertdevicepathtotext 
// 
//typedef
//CHAR16*
//(EFIAPI *EFI_DEVICE_PATH_TO_TEXT_PATH) (
//  IN CONST EFI_DEVICE_PATH_PROTOCOL       *DevicePath,
//  IN BOOLEAN                              DisplayOnly,
//  IN BOOLEAN                              AllowShortcuts
//  );
//
//
// 
// Use BootServices-> HandleProtocol to retrieve pointer to LoadedImageProtocol interface 
//typedef
//EFI_STATUS
//(EFIAPI *EFI_HANDLE_PROTOCOL) (
//   IN EFI_HANDLE                    Handle,
//   IN EFI_GUID                      *Protocol,
//   OUT VOID                         **Interface
//   );
// Use LoadedImageProtocol->DeviceHandle as Input EFI_HANDLE for another call
// now, use  BootServices-> HandleProtocol to retrieve pointer to i
// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL interface 
//
//

{
	EFI_BOOT_SERVICES *gBS=(SystemTable->BootServices);
	EFI_LOADED_IMAGE_PROTOCOL *loadedimageprotocol;
 //	EFI_LOADED_IMAGE *loadedimage;
	EFI_GUID lip_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
	EFI_STATUS status;
	
	status = gBS->HandleProtocol(
		ImageHandle,
		&lip_guid,
		(void **) &loadedimageprotocol
	);
	if (status == EFI_SUCCESS) {
		EFI_HANDLE devicehandle = loadedimageprotocol->DeviceHandle;
		EFI_DEVICE_PATH_PROTOCOL *devicefilepath = (loadedimageprotocol->FilePath);
		UINT64 img_size=loadedimageprotocol->ImageSize;
		EFI_DEVICE_PATH_PROTOCOL *devicepath;
		EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfsp;
		EFI_GUID sfsp_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
		
		//EFI_DEVICE_PATH_PROTOCOL *devicepath = (loadedimageprotocol->FilePath);
		EFI_GUID e_lidpp_guid= EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID;
		//sfsp_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

		status = gBS->HandleProtocol(
			ImageHandle,
			&e_lidpp_guid,
			(void **) &devicepath
		);

		status = gBS->HandleProtocol(
			devicehandle,
			&sfsp_guid,
			(void **) &sfsp
		);
		EFI_FILE_PROTOCOL *rootvolume;
		//EFI_FILE_HANDLE rootvolume;
		//EFI_FILE_HANDLE srcfile;
		//EFI_FILE_HANDLE destfile;
		status = sfsp->OpenVolume(sfsp, &rootvolume);
		/*
		*	
		*	 Now copy this file to new target file with Open, Write and Close sequence
		*	 of functions (protocols) available to EFI_FILE_PROTOCOL
		*	
		*	 typedef
		*	 EFI_STATUS
		*	 (EFIAPI *EFI_FILE_OPEN) (
		*	   IN EFI_FILE_PROTOCOL                  *This,
		*	   OUT EFI_FILE_PROTOCOL                 **NewHandle,
		*	   IN CHAR16                             *FileName,
		*	   IN UINT64                             OpenMode,
		*	   IN UINT64                             Attributes
		*	   );
		*	 
		*	
		*	 typedef
		*	 EFI_STATUS
		*	 (EFIAPI *EFI_FILE_WRITE) (
		*	   IN EFI_FILE_PROTOCOL              *This,
		*	   IN OUT UINTN                      *BufferSize,
		*	   IN VOID                           *Buffer
		*	   );
		*	 
		*	 typedef
		*	 EFI_STATUS
		*	 (EFIAPI *EFI_FILE_READ) (
		*	   IN EFI_FILE_PROTOCOL           *This,
		*	   IN OUT UINTN                   *BufferSize,
		*	   OUT VOID                       *Buffer
		*	   );
		*	
		*	 Close():
		*	 typedef
		*	 EFI_STATUS
		*	 (EFIAPI *EFI_FILE_CLOSE) (
		*	   IN EFI_FILE_PROTOCOL                     *This
		*	   );
		*	
		*/
		if (status == EFI_SUCCESS) {
			EFI_FILE_PROTOCOL *hostfile = NULL;
			//EFI_FILE_PROTOCOL *hostfile = destfile;
			//EFI_FILE_PROTOCOL *destfile = NULL;
			EFI_FILE_PROTOCOL *targetfile = NULL;
			//UINT64 host_attribs = 0x0000000000000001 || 0x0000000000000002 || 0x0000000000000004;
			UINT64 host_attribs = 0x0000000000000000;
			//EFI_FILE_INFO *fileinfo;
			//EFI_GUID fileinfo_guid = EFI_FILE_INFO_ID;
			//VOID *fileinfo_buffer = NULL;
			//UINTN fileinfo_buffersize = 0;
			
			UINTN newfile_buffersize = 0x2000;
			VOID *temp_buf;
			//UINT64 target_attribs = 0x0000000000000002 || 0x0000000000000004;
			status = rootvolume->Open(rootvolume, &hostfile, L"\\ImageOffTheHandle.efi",0x0000000000000001, host_attribs);
			if (status == EFI_SUCCESS){
				Print(L"open root volume successful\n\n!");
				//open() -> read() -> close() host
				//EFI_FILE_INFO *hostfileinfo;
				
				/*status = gBS->AllocatePool(
					AllocateAnyPages,
					img_size,
					(void**)&hostfile); 
				*/
				//EFI_FILE_HANDLE *temp_buf;
				//EFI_FILE_PROTOCOL *temp_buf;
				
				/*if (status == EFI_BUFFER_TOO_SMALL){
					status = gBS->AllocatePool(
						AllocateAnyPages,
						img_size,
						(void**)&hostfile); 
					
					if (status==EFI_SUCCESS){
						Print(L"allocate pool for file read successful!\n\n");
					}
				} else {

						Print(L"initial allocate pool for file read successful!\n\n");
				}*/
					
				/*status=hostfile->GetInfo(hostfile, &fileinfo_guid, &fileinfo_buffersize, NULL);
				if (EFI_ERROR(status)){
					Print(L" hmm something got effed.\n\n");
				} else if (status == EFI_BUFFER_TOO_SMALL){
					status = gBS->AllocatePool(
						AllocateAnyPages,
						fileinfo_buffersize,
						(void**)&fileinfo); 
				
					status=hostfile->GetInfo(hostfile, &fileinfo_guid, &fileinfo_buffersize, fileinfo);
					if (status == EFI_SUCCESS){
						Print(L"2nd get info call successful! \n\n");
					}
				}
				if (status == EFI_SUCCESS){
					Print(L"get info call successful! \n\n");
				}
				UINTN testnewfile_buffersize=(fileinfo->FileSize);	
				Print(L"newfile buffer size is: %u \n\n", &testnewfile_buffersize);
				*/

				status = gBS->AllocatePool(
					AllocateAnyPages,
					newfile_buffersize,
					(void**)&temp_buf); 
				//EFI_FILE_HANDLE is a void* so this takes care of param requirements for this function
	//			UINTN target_filesz=img_size;
				//status=rootvolume->Read(hostfile, &img_size, &temp_buf);
				if (status==EFI_SUCCESS){
					Print(L"allocate pool for file read successful!\n\n");
				}
				
				//status=hostfile->Read(hostfile, &img_size, temp_buf);
				status=hostfile->Read(hostfile, &newfile_buffersize, temp_buf);
				if (status == EFI_SUCCESS){
					Print(L"file read with ImageOffTheHandle.efi successful! \n\n");
				}

				// open -> write -> close target		
				//status=rootvolume->Open(rootvolume, &targetfile, L"\\4.efi", 0x8000000000000000, host_attribs);
				
				status  = rootvolume->Open(rootvolume, &targetfile, L"\\4.efi", EFI_FILE_MODE_READ |  EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
				if (EFI_ERROR(status)){
					Print(L"error with create file call... \n\n");
				} else if (status == EFI_SUCCESS){
					Print(L"yay create file call was successful!!\n\n");
				}
				status=targetfile->Write(targetfile, &newfile_buffersize, temp_buf);
				if (EFI_ERROR(status)){
					Print(L"error with writing new file... \n\n");
				} else if (status == EFI_SUCCESS){
					Print(L"yay write file call was successful!!\n\n");
				}
				status=targetfile->Close(targetfile);
				if (EFI_ERROR(status)){
					Print(L"error with close file call... \n\n");
				};

				
				
				for (UINTN i=0; i < 0x100; i++){
					//Print(L"%c", &(temp_buf + i*sizeof(UINT16)));
					Print(L"%c", ((CHAR8 *)temp_buf)[i]);
				};
		//		Print(L"Device path of current UEFI app executable image: %s\n", Volume->GetInfo()t(
		//		EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *dpttp;
		//		EFI_GUID dpttp_guid = EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID;
		//		Print(L"Device path of current UEFI app executable image: %s\n", ConvertDevicePathToText(loadedimage
				Print(L"Filename current UEFI app executable image: %s\n", ConvertDevicePathToText(devicefilepath ,FALSE,TRUE));
				Print(L"Device path of current UEFI app executable image: %s\n", ConvertDevicePathToText(devicepath, FALSE,TRUE));
				Print(L"Image size of current UEFI app executable image: %X\n", img_size);
				gBS->FreePool(temp_buf);
				//gBS->FreePool(fileinfo);
				status=hostfile->Close(hostfile);
				rootvolume->Close(rootvolume);
	//		for (int i=0; i < 16; i++){
	//			//Print(L"%c", &(temp_buf + i*sizeof(UINT16)));
	//			Print(L"%c", temp_buf[i]);
	//		};
			} else {
				Print(L" hmm open root volum unsuccessful... something got effed.");
			}
		} else {
			Print(L" hmm something got effed.");
		}
	}
	return status;		

}

//{
//	EFI_BOOT_SERVICES *gBS=(SystemTable->BootServices);
////	EFI_LOCATE_PROTOCOL locateProtocolHook=(gBS->LocateProtocol);
//	UINTN MemoryMapSize = 0;
//	EFI_MEMORY_DESCRIPTOR *MemoryMap = NULL;
//	UINTN MapKey;
//	UINTN DescriptorSize;
//	UINT32 DescriptorVersion;
//
//	EFI_STATUS Mem_Status;
//	//MemoryMap is an array of EFI_MEMORY_DESCRIPTORs
//	//see detailed notes here: https://github.com/Kostr/UEFI-Lessons/tree/master/Lessons/Lesson_11
//	//also see this part of the EDK2 reference code: 
//	//https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Uefi/UefiSpec.h#L160
//
//	//UEFI BootServices.GetMemoryMap() prototype:
//	/*	typedef
//	/	EFI_STATUS
//	/	(EFIAPI \*EFI_GET_MEMORY_MAP) (
//	/	   IN OUT UINTN                  *MemoryMapSize,
//	/	   OUT EFI_MEMORY_DESCRIPTOR     *MemoryMap,
//	/	   OUT UINTN                     *MapKey,
//	/	   OUT UINTN                     *DescriptorSize,
//	/	   OUT UINT32                    *DescriptorVersion
//  	/	);
//	/ from: https://uefi.org/specs/UEFI/2.9_A/07_Services_Boot_Services.html#efi-boot-services-getmemorymap
//	*/
//	
//	//	And the relevant,related prototype for EFI_MEMORY_DESCRIPTOR:
//	/*****************************************************/
//	//EFI_MEMORY_DESCRIPTOR
//	/******************************************************
//	/typedef struct {
//	/   UINT32                     Type;
//	/   EFI_PHYSICAL_ADDRESS       PhysicalStart;
//	/   EFI_VIRTUAL_ADDRESS        VirtualStart;
//	/   UINT64                     NumberOfPages;
//	/   UINT64                     Attribute;
//	/  } EFI_MEMORY_DESCRIPTOR;
//	/	/
//	*/
//	
//	Mem_Status = gBS->GetMemoryMap(
//		&MemoryMapSize,
//		MemoryMap,
//		&MapKey,
//		&DescriptorSize,
//		&DescriptorVersion
//	);
//	//This call populates MemoryMapSize with the correct size of the MemoryMap
//	// to be used in the next call for allocating sufficient memory for the MemoryMap with AllocatePool()
//	
//	if (Mem_Status == EFI_BUFFER_TOO_SMALL){
//
//		//EfiBootServicesData; 
//		//default memory type used by uefi boot service's driver when allocating memory with AllocatePool()
//		// see EfiMemoryTypes reference info here: https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Uefi/UefiMultiPhase.h
//		Mem_Status = gBS->AllocatePool(
//			EfiBootServicesData,
//			MemoryMapSize,
//			(void**)&MemoryMap); 
//		
//		// see this reference for uefi driver writer's guide to avoiding compiler warnings re: type checking:
//		// https://github.com/tianocore-docs/edk2-UefiDriverWritersGuide/blob/master/4_general_driver_design_guidelines/41_common_coding_practices/411_type_checking.md
//		// basically, we want this convention for avoiding a type confusion compiler warning: 
//		// (void**) &MyStructure;
//		// So typically we would do something like this:
//		//	sizeof(MAPSTRUCT),
//		//	(void**)&MAPSTRUCT); 
//		if (! EFI_ERROR(Mem_Status)) {	
//			Mem_Status = gBS->GetMemoryMap(
//				&MemoryMapSize,
//				MemoryMap,
//				&MapKey,
//				&DescriptorSize,
//				&DescriptorVersion
//			);
//			//Virtual Size must be aligned on 4 kb boundary so address range for each EFI_MEMORY_DESCRIPTOR struct in the returned list
//			// will be [PhysicalStart, PhysicalStart + numberOfPages * 4096 - 1]
//			//so we can use this as our address range to print
//			//this should be equal to DescriptorSize for each EFI_MEMORY_DESCRIPTOR ( which is a list of structs that we are traversing;
//			//DescriptorSize corresponds to the head of the list with respect to our place in it, so DescriptorSize will update each time
//			// and we can use that as the increment value of our address pointer;)
//		EFI_MEMORY_DESCRIPTOR *efimemmap = MemoryMap;
//		UINTN PAGESIZE = 4096;
//		
//		while (((UINT8*) efimemmap) < (UINT8*)MemoryMap + MemoryMapSize){
//			UINTN efimmap_size = (UINTN) efimemmap->NumberOfPages * PAGESIZE;	
//			//UINTN efimmap_type = (UINTN) efimemmap->Type;
//			UINTN efimmap_adrstart = (UINTN) efimemmap->PhysicalStart;
//			//UINTN efimmap_attrs = (UINTN) efimemmap->Attribute;
//			
//			Print(L"Identified Memory Map EFI_MEMORY_DESCRIPTOR address range: %016llx %016llx \n\n", efimmap_adrstart ,  efimmap_adrstart + efimmap_size);	
//			//Print(L"Identified Memory Map EFI_MEMORY_DESCRIPTOR type: %s and attributes: %s \n\n", &efimmap_type ,  &efimmap_attrs);	
//			efimemmap = (EFI_MEMORY_DESCRIPTOR*) (efimemmap + DescriptorSize);
//		}
//	}
//	gBS->FreePool(MemoryMap);
//	}
//
//	//SystemTable->ConOut->OutputString(SystemTable->ConOut, L"hello from the other side\n");
//	return Mem_Status;
//}
////	Print(L"Boot Services Table address is: %p \n\n", &gBS);	
////	Print(L"Boot Services LocateHandleBuffer() function pointer  address is: %p \n\n", &locateProtocolHook);	
//	//SystemTable->ConOut->OutputString(SystemTable->ConOut,L"%s", &bootservicestest);
////	/*for(int i=0; i < sizeof bootserviceaddress; i++){
////		SystemTable->ConOut->OutputString(SystemTable->ConOut, bst_adr[i]);
////	}*/
////}
