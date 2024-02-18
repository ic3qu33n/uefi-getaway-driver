#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleTextOut.h>
#include <Guid/FileInfo.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PcdLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Protocol/AcpiSystemDescriptionTable.h>

EFI_STATUS
EFIAPI
SmmCalloutDriverEntryPoint (
	IN EFI_HANDLE			ImageHandle,
	IN EFI_SYSTEM_TABLE		*SystemTable
	)

/****************************************************************************************
 References: 
 ****************************************************************************************
 This repo of example UEFI apps by PF-Maillard:
 https://github.com/PF-Maillard/UEFI_BMP_Application/tree/master
	Specifically this file:
 https://github.com/PF-Maillard/UEFI_BMP_Application/blob/master/MyBmpApplication.c

 This repo of UEFI sample apps/tutorials on different aspects of UEFI dev:
 https://github.com/Kostr/UEFI-Lessons/tree/master
 ty Kostr for this amazing repo, truly one of the best UEFI learning resources I've found
 <3

 ****************************************************************************************

 ****************************************************************************************

 ****************************************************************************************
 Relevant struct definitions (and their corresponding URLs) from the UEFI spec are below:
 ****************************************************************************************

 EFI_LOADED_IMAGE_PROTOCOL struct:

 typedef struct {
   UINT32                        Revision;
   EFI_HANDLE                    ParentHandle;
   EFI_System_Table              *SystemTable;

   // Source location of the image
   EFI_HANDLE                    DeviceHandle;
   EFI_DEVICE_PATH_PROTOCOL      *FilePath;
   VOID                          *Reserved;

   // Image’s load options
   UINT32                        LoadOptionsSize;
   VOID                          *LoadOptions;

   // Location where image was loaded
   VOID                          *ImageBase;
   UINT64                        ImageSize;
   EFI_MEMORY_TYPE               ImageCodeType;
   EFI_MEMORY_TYPE               ImageDataType;
   EFI_IMAGE_UNLOAD              Unload;
} EFI_LOADED_IMAGE_PROTOCOL;


 Two most relevant protocols here are 
 EFI_LOADED_IMAGE_PROTOCOL
 and
 EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL
 For more details, see overview here:
 https://uefi.org/specs/UEFI/2.10/09_Protocols_EFI_Loaded_Image.html

 also note that  EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL
 and EFI_DEVICE_PATH_PROTOCOL
 are the same, they just have diff GUIDs

 For details on EFI_DEVICE_PATH_PROTOCOL see:
  https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#efi-device-path-protocol
 
	Protocol interface structure for EFI_DEVICE_PATH_PROTOCOL (from above link):
******************************************************
 EFI_DEVICE_PATH_PROTOCOL
******************************************************
typedef struct _EFI_DEVICE_PATH_PROTOCOL {
  UINT8           Type;
  UINT8           SubType;
  UINT8           Length[2];
 } EFI_DEVICE_PATH_PROTOCOL;



 EFI_LOADED_IMAGE_PROTOCOL -> DeviceHandle -> VolumeHandle
 EFI_SIMPLE_FILE_SYSTEM_PROTOCOL -> OpenVolume

 From UEFI Spec:
 https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html#efi-simple-file-system-protocol-openvolume

 typedef
EFI_STATUS
(EFIAPI *EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME) (
  IN EFI_SIMPLE_FILE_SYSTEM PROTOCOL                   *This,
  OUT EFI_FILE_PROTOCOL                                **Root
  );

 Finally, use EFI_FILE_PROTOCOL->EFI_FILE_OPEN to creae a new file
 see  https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/SimpleFileSystem.h#L115
 EFI_FILE_OPEN prototype is below:
**
******************************************************
 EFI_FILE_OPEN
******************************************************
  Opens a new file relative to the source file's location.

  @param  This       A pointer to the EFI_FILE_PROTOCOL instance that is the file
                     handle to the source location. This would typically be an open
                     handle to a directory.
  @param  NewHandle  A pointer to the location to return the opened handle for the new
                     file.
  @param  FileName   The Null-terminated string of the name of the file to be opened.
                     The file name may contain the following path modifiers: "\", ".",
                     and "..".
  @param  OpenMode   The mode to open the file. The only valid combinations that the
                     file may be opened with are: Read, Read/Write, or Create/Read/Write.
  @param  Attributes Only valid for EFI_FILE_MODE_CREATE, in which case these are the
                     attribute bits for the newly created file.

  @retval EFI_SUCCESS          The file was opened.
  @retval EFI_NOT_FOUND        The specified file could not be found on the device.
  @retval EFI_NO_MEDIA         The device has no medium.
  @retval EFI_MEDIA_CHANGED    The device has a different medium in it or the medium is no
                               longer supported.
  @retval EFI_DEVICE_ERROR     The device reported an error.
  @retval EFI_VOLUME_CORRUPTED The file system structures are corrupted.
  @retval EFI_WRITE_PROTECTED  An attempt was made to create a file, or open a file for write
                               when the media is write-protected.
  @retval EFI_ACCESS_DENIED    The service denied access to the file.
  @retval EFI_OUT_OF_RESOURCES Not enough resources were available to open the file.
  @retval EFI_VOLUME_FULL      The volume is full.


typedef
EFI_STATUS
(EFIAPI *EFI_FILE_OPEN)(
  IN EFI_FILE_PROTOCOL        *This,
  OUT EFI_FILE_PROTOCOL       **NewHandle,
  IN CHAR16                   *FileName,
  IN UINT64                   OpenMode,
  IN UINT64                   Attributes
  );

//
// Open modes
//
#define EFI_FILE_MODE_READ    0x0000000000000001ULL
#define EFI_FILE_MODE_WRITE   0x0000000000000002ULL
#define EFI_FILE_MODE_CREATE  0x8000000000000000ULL

//
// File attributes
//
#define EFI_FILE_READ_ONLY   0x0000000000000001ULL
#define EFI_FILE_HIDDEN      0x0000000000000002ULL
#define EFI_FILE_SYSTEM      0x0000000000000004ULL
#define EFI_FILE_RESERVED    0x0000000000000008ULL
#define EFI_FILE_DIRECTORY   0x0000000000000010ULL
#define EFI_FILE_ARCHIVE     0x0000000000000020ULL
#define EFI_FILE_VALID_ATTR  0x0000000000000037ULL

 
 EFI_DEVICE_PATH_TO_TEXT_PROTOCOL.ConvertDevicePathToText()
 from UEFI spec, see reference:
 https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html?#efi-device-path-to-text-protocol-convertdevicepathtotext 
 
typedef
CHAR16*
(EFIAPI *EFI_DEVICE_PATH_TO_TEXT_PATH) (
  IN CONST EFI_DEVICE_PATH_PROTOCOL       *DevicePath,
  IN BOOLEAN                              DisplayOnly,
  IN BOOLEAN                              AllowShortcuts
  );


 ##This was the original function call used, changed to OpenProtocol() 
 Use BootServices-> HandleProtocol to retrieve pointer to LoadedImageProtocol interface 
typedef
EFI_STATUS
(EFIAPI *EFI_HANDLE_PROTOCOL) (
   IN EFI_HANDLE                    Handle,
   IN EFI_GUID                      *Protocol,
   OUT VOID                         **Interface
   );


Use OpenProtocol()
typedef
EFI_STATUS
(EFIAPI *EFI_OPEN_PROTOCOL) (
   IN EFI_HANDLE                    Handle,
   IN EFI_GUID                      *Protocol,
   OUT VOID                         **Interface OPTIONAL,
   IN EFI_HANDLE                    AgentHandle,
   IN EFI_HANDLE                    ControllerHandle,
   IN UINT32                        Attributes
   );


Relevant Attributes:
#define EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL   0x00000001
#define EFI_OPEN_PROTOCOL_GET_PROTOCOL         0x00000002
#define EFI_OPEN_PROTOCOL_TEST_PROTOCOL        0x00000004
#define EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER  0x00000008
#define EFI_OPEN_PROTOCOL_BY_DRIVER            0x00000010
#define EFI_OPEN_PROTOCOL_EXCLUSIVE            0x00000020


EFI_LOADED_IMAGE_PROTOCOL *loadedimageprotocol;
gBS->OpenProtocol(
ImageHandle,
&lip_guid,
(void**)&loadedimageprotocol,
ImageHandle,
NULL,
EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL)


 Use LoadedImageProtocol->DeviceHandle as Input EFI_HANDLE for another call
 now, use  BootServices-> HandleProtocol to retrieve pointer to i
 EFI_SIMPLE_FILE_SYSTEM_PROTOCOL interface 
****************************************************************************************/


{
	EFI_BOOT_SERVICES *gBS=(SystemTable->BootServices);
	//EFI_LOADED_IMAGE_PROTOCOL *loadedimageprotocol;
	//EFI_GUID lip_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
	//EFI_GUID gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
	//EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
	EFI_STATUS status;
	//EFI_HANDLE *handlebuffer;
	//UINTN handle_count;
	EFI_ACPI_SDT_PROTOCOL *efi_acpi_sdt_protocol;	
	EFI_GUID acpi_sdt_guid = EFI_ACPI_SDT_PROTOCOL_GUID;

	EFI_ACPI_SDT_HEADER *efi_acpi_table;	
	EFI_ACPI_TABLE_VERSION version;
	UINTN index = 0;
	UINTN tablekey;
	
	Print(L"EFI SYSTEM TABLE pointer address: %p \n", &SystemTable);
	Print(L"EFI BOOT SERVICES TABLE pointer  address is: %p \n\n", &gBS);	
	//Print(L"EFI_LOADED_IMAGE_PROTOCOL pointer  address is: %p \n\n", &loadedimageprotocol);	
	/*status = gBS->HandleProtocol(
		ImageHandle,
		&lip_guid,
		(void **) &efi_acpi_sdt_protocol
	*/
	
	status= gBS->LocateProtocol(
		&acpi_sdt_guid,
		NULL,
		(void **)&efi_acpi_sdt_protocol
	);
	if (EFI_ERROR(status)){
		return status;
	}
	while(TRUE){
	
		status=efi_acpi_sdt_protocol->GetAcpiTable(index, &efi_acpi_table, &version, &tablekey); 
		if (EFI_ERROR(status)){
			return status;
		}
		if (((CHAR8)((efi_acpi_table->Signature >> 0)&0xFF) == 'U') &&
			((CHAR8)((efi_acpi_table->Signature >> 8)&0xFF) == 'E') &&
			((CHAR8)((efi_acpi_table->Signature >> 16)&0xFF) == 'F') &&
			((CHAR8)((efi_acpi_table->Signature >> 24)&0xFF) == 'I')){
				Print(L"UEFI table found at %p with length 0x%x \n", efi_acpi_table, efi_acpi_table->Length);
				break;
		}
		else {
			Print(L"Found ACPI Table: %c %c %c %c at %p with length: 0x%x \n", 
					(CHAR8)((efi_acpi_table->Signature >> 0)&0xFF),
					(CHAR8)((efi_acpi_table->Signature >> 8)&0xFF),
					(CHAR8)((efi_acpi_table->Signature >> 16)&0xFF),
					(CHAR8)((efi_acpi_table->Signature >> 24)&0xFF),
					efi_acpi_table,
					efi_acpi_table->Length);
		}
		index++;
	}
	return status;		
}


EFI_STATUS
EFIAPI
SmmCalloutDriverUnload (
	EFI_HANDLE ImageHandle
	)
{
		Print(L"unloading Smm Callout Driver");
		return EFI_SUCCESS;
}


