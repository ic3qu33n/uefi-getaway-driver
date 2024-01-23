#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/GraphicsOutput.h>
#include <Protocol/SimpleTextOut.h>
#include <Guid/FileInfo.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PcdLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/BmpSupportLib.h>
#include <IndustryStandard/Bmp.h>

EFI_STATUS
EFIAPI
GOPComplexEntryPoint (
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
	typedef struct EFI_GRAPHICS_OUTPUT_PROTCOL {
	 EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE     QueryMode;
	 EFI_GRAPHICS_OUTPUT_PROTOCOL_SET_MODE       SetMode;
	 EFI_GRAPHICS_OUTPUT_PROTOCOL_BLT            Blt;
	 EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE           *Mode;
	} EFI_GRAPHICS_OUTPUT_PROTOCOL;

	typedef struct {
	 UINT32                    Version;
	 UINT32                    HorizontalResolution;
	 UINT32                    VerticalResolution;
	 EFI_GRAPHICS_PIXEL_FORMAT PixelFormat;
	 EFI_PIXEL_BITMASK         PixelInformation;
	 UINT32                    PixelsPerScanLine;
	} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;

	typedef struct {
	  UINT32                                    MaxMode;
	  UINT32                                    Mode;
	  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION      *Info;
	 UINTN                                      SizeOfInfo;
	  EFI_PHYSICAL_ADDRESS                      FrameBufferBase;
	  UINTN                                     FrameBufferSize;
	} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;

	typedef
	EFI_STATUS
	(EFIAPI *EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE) (
	 IN EFI_GRAPHICS_OUTPUT_PROTOCOL              *This,
	 IN UINT32                                    ModeNumber,
	 OUT UINTN                                    *SizeOfInfo
	 OUT EFI_GRAPHICS_OUTPUT_MODE_INFORMATION     **Info
	 );
	typedef
	EFI_STATUS
	(EFIAPI *EFI_GRAPHICS_OUTPUT_PROTOCOL_SET_MODE) (
	 IN EFI_GRAPHICS_OUTPUT_PROTOCOL                *This,
	 IN UINT32                                      ModeNumber
	 );

	typedef struct {
	 UINT8                        Blue;
	 UINT8                        Green;
	 UINT8                        Red;
	 UINT8                        Reserved;
	} EFI_GRAPHICS_OUTPUT_BLT_PIXEL;

	typedef enum {
	 EfiBltVideoFill,
	 EfiBltVideoToBltBuffer,
	 EfiBltBufferToVideo,
	 EfiBltVideoToVideo,
	 EfiGraphicsOutputBltOperationMax
	} EFI_GRAPHICS_OUTPUT_BLT_OPERATION;

	typedef
	EFI_STATUS
	(EFIAPI *EFI_GRAPHICS_OUTPUT_PROTOCOL_BLT) (
	 IN EFI_GRAPHICS_OUTPUT_PROTOCOL                 *This,
	 IN OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL            *BltBuffer, OPTIONAL
	 IN EFI_GRAPHICS_OUTPUT_BLT_OPERATION            BltOperation,
	 IN UINTN                                        SourceX,
	 IN UINTN                                        SourceY,
	 IN UINTN                                        DestinationX,
	 IN UINTN                                        DestinationY,
	 IN UINTN                                        Width,
	 IN UINTN                                        Height,
	 IN UINTN                                        Delta OPTIONAL
	 );

BMP struct, from: https://github.com/tianocore/edk2/blob/master/MdePkg/Include/IndustryStandard/Bmp.h
typedef struct {
  CHAR8     CharB;
  CHAR8     CharM;
  UINT32    Size;
  UINT16    Reserved[2];
  UINT32    ImageOffset;
  UINT32    HeaderSize;
  UINT32    PixelWidth;
  UINT32    PixelHeight;
  UINT16    Planes;              ///< Must be 1
  UINT16    BitPerPixel;         ///< 1, 4, 8, or 24
  UINT32    CompressionType;
  UINT32    ImageSize;           ///< Compressed image size in bytes
  UINT32    XPixelsPerMeter;
  UINT32    YPixelsPerMeter;
  UINT32    NumberOfColors;
  UINT32    ImportantColors;
} BMP_IMAGE_HEADER;
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
	EFI_LOADED_IMAGE_PROTOCOL *loadedimageprotocol;
	EFI_GUID lip_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
	EFI_GUID gop_guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
	EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
	EFI_STATUS status;
	EFI_HANDLE *handlebuffer;
	UINTN handle_count;
	

	Print(L"EFI SYSTEM TABLE pointer address: %p \n", &SystemTable);
	Print(L"EFI BOOT SERVICES TABLE pointer  address is: %p \n\n", &gBS);	
	Print(L"EFI_LOADED_IMAGE_PROTOCOL pointer  address is: %p \n\n", &loadedimageprotocol);	
	status = gBS->HandleProtocol(
		ImageHandle,
		&lip_guid,
		(void **) &loadedimageprotocol
	);
	
	/*status= gBS->LocateProtocol(
		&gop_guid,
		NULL,
		(void**)&gop);
	*/

	status= gBS->LocateHandleBuffer(
		ByProtocol,
		&gop_guid,
		NULL,
		&handle_count,
		&handlebuffer);
	
	if (EFI_ERROR(status)){
		Print(L"EFI GOP not found. :( \n");
		return status;
	}
	status= gBS->HandleProtocol(
		handlebuffer[0],
		&gop_guid,
		(void**)&gop);


/*	status= gBS->OpenProtocol(
		ImageHandle,
		&gop_guid,
		(void**)&gop,
		ImageHandle,
		NULL,
		EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
	

	typedef struct {
	 UINT32                    Version;
	 UINT32                    HorizontalResolution;
	 UINT32                    VerticalResolution;
	 EFI_GRAPHICS_PIXEL_FORMAT PixelFormat;
	 EFI_PIXEL_BITMASK         PixelInformation;
	 UINT32                    PixelsPerScanLine;
	} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;
	
	typedef
	EFI_STATUS
	(EFIAPI *EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE) (
	 IN EFI_GRAPHICS_OUTPUT_PROTOCOL              *This,
	 IN UINT32                                    ModeNumber,
	 OUT UINTN                                    *SizeOfInfo
	 OUT EFI_GRAPHICS_OUTPUT_MODE_INFORMATION     **Info
	 );
	typedef
	EFI_STATUS
	(EFIAPI *EFI_GRAPHICS_OUTPUT_PROTOCOL_SET_MODE) (
	 IN EFI_GRAPHICS_OUTPUT_PROTOCOL                *This,
	 IN UINT32                                      ModeNumber
	 );
	typedef struct {
	  UINT32                                    MaxMode;
	  UINT32                                    Mode;
	  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION      *Info;
	 UINTN                                      SizeOfInfo;
	  EFI_PHYSICAL_ADDRESS                      FrameBufferBase;
	  UINTN                                     FrameBufferSize;
	} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;

	[From "BmpSupportLib.h" - TranslateBmpToGotBlt]
	RETURN_STATUS
	EFIAPI
	TranslateBmpToGopBlt (
	  IN     VOID                           *BmpImage,
	  IN     UINTN                          BmpImageSize,
	  IN OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  **GopBlt,
	  IN OUT UINTN                          *GopBltSize,
	  OUT    UINTN                          *PixelHeight,
	  OUT    UINTN                          *PixelWidth
	  );

	void* gbs_handle_protocol = (gBS->HandleProtocol);
	Print(L"Boot Services HandleProtocol pointer  address is: %p \n\n", &gbs_handle_protocol);
*/
	
	if (status == EFI_SUCCESS) {
		Print(L"EFI BootServices OpenProtocol call with gop was successful: %p \n", &gop);
		UINT64 size_info;
	 	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *gop_info;
	  	EFI_PHYSICAL_ADDRESS framebuffer_base;
	  	UINTN framebuffer_size;
		status = gop->QueryMode(gop, gop->Mode->Mode, &size_info, &gop_info);
		if (status== EFI_NOT_STARTED){
			status = gop->SetMode(gop, 0);
		} else {
			UINT32 gop_curr_mode=gop->Mode->Mode;
			UINT32 gop_num_modes=gop->Mode->MaxMode;
			framebuffer_base = gop->Mode->FrameBufferBase;
			framebuffer_size = gop->Mode->FrameBufferSize;
			Print(L"EFI_GOP Current Mode %d: \n GOP Num Modes: %d\n\n", &gop_curr_mode, &gop_num_modes);
			Print(L"EFI_GOP Framebuffer base %d: \n Framebuffer Size: %d\n\n", &framebuffer_base, &framebuffer_size);
	 		UINT32 horiz_rez; 
	 		UINT32 vert_rez; 
	 		EFI_GRAPHICS_PIXEL_FORMAT pixelformat;
			for (int i=0; i<gop_num_modes; i++){
				status = gop->QueryMode(gop, i, &size_info, &gop_info);
				horiz_rez=gop_info->HorizontalResolution;
				vert_rez=gop_info->VerticalResolution;
				pixelformat=gop_info->PixelFormat;
				Print(L"EFI_GOP Mode %d: \n Vertical Resolution: %d \n Horizontal Resolution: %d \nPixel format: %s \n\n", &horiz_rez, &vert_rez, &pixelformat);
			}
	
			status = gop->SetMode(gop, gop->Mode->Mode);
			if (status == EFI_SUCCESS) {
				Print(L"EFI GOP SetMode call successful: %p \n", &(gop->Mode->Mode));
			}
			EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *sfsp;
			EFI_GUID sfsp_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
			EFI_HANDLE devicehandle = loadedimageprotocol->DeviceHandle;
			//EFI_GUID e_lidpp_guid= EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID;
			/*
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
			*/
		
			status= gBS->OpenProtocol(
				devicehandle,
				&sfsp_guid,
				(void**)&sfsp,
				ImageHandle,
				NULL,
				EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
			if (status == EFI_SUCCESS) {
				Print(L"EFI BootServices OpenProtocol call with simplefilesystemprotocol was successful: %p \n", &loadedimageprotocol);
				Print(L"EFI_SIMPLE_FILE_SYSTEM_PROTOCOL pointer  address is: %p \n\n", &sfsp);	
			}
			EFI_FILE_PROTOCOL *rootvolume;
			status = sfsp->OpenVolume(sfsp, &rootvolume);
			
			Print(L"EFI_SIMPLE_FILE_SYSTEM_PROTOCOL OpenVolume() func address is: %p \n\n", &(sfsp->OpenVolume));	
			Print(L"EFI_FILE_PROTOCOL rootVolume pointer  address is: %p \n\n", &rootvolume);	
			/*
			*	
			*	 Now copy this file to new target file with Open, Write and Close sequence
			*	 of functions (protocols) available to EFI_FILE_PROTOCOL
			*
			*	host (source) file:	
			*	open() -> read() -> close()
			*
			*	target (destination) file:	
			*	open() -> write() -> close()
			*
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
				EFI_FILE_PROTOCOL *targetfile = NULL;
				UINT64 host_attribs = 0x0000000000000000;
				EFI_FILE_INFO bmp_file_info;
				EFI_GUID file_info_guid = EFI_FILE_INFO_ID;
				UINTN bmpfileinfo_size = sizeof(bmp_file_info);
				//SIZE_OF_EFI_FILE_INFO; 
				//set buffer size (destination file img_size) == original img_size	
				//UINTN newfile_buffersize =(UINTN) img_size;
				UINTN newfile_buffersize;
				VOID *temp_buf;
				EFI_GRAPHICS_OUTPUT_BLT_PIXEL *bmp_gop = NULL;
				UINTN bmp_pixelheight = 0;
				UINTN bmp_pixelwidth = 0;
				UINTN gopbltsize = 0;
				BMP_IMAGE_HEADER* bmp=(BMP_IMAGE_HEADER*)&temp_buf;
				EFI_FILE_OPEN *open_func=&(rootvolume->Open);
				Print(L"EFI_FILE_OPEN Open() function pointer  address is: %p \n\n", &open_func);
				//status = rootvolume->Open(rootvolume, &hostfile, L"\\skull2.bmp",0x0000000000000001, host_attribs);
				status = rootvolume->Open(rootvolume, &hostfile, L"\\Logo.bmp",0x0000000000000001, host_attribs);
				if (status == EFI_SUCCESS){
					Print(L"open root volume successful\n\n!");
					
					status=hostfile->GetInfo(hostfile, &file_info_guid, &bmpfileinfo_size, NULL);
					if (status == EFI_BUFFER_TOO_SMALL){
						status = gBS->AllocatePool(
							AllocateAnyPages,
							bmpfileinfo_size,
							(void**)&bmp_file_info); 
					}
					status=hostfile->GetInfo(hostfile, &file_info_guid, &bmpfileinfo_size, (void*)&bmp_file_info);
					if (status == EFI_SUCCESS){
						Print(L"get info for BMP file successful!\n\n");
						//UINT64 bmpsize = bmpfileinfo->Size;
						UINT64 bmpfilesize = bmp_file_info.FileSize;
						CHAR16 *bmpfilename = bmp_file_info.FileName;
						Print(L"Name of BMP file: %s \n Physical size of BMP file: %llu \n", &bmpfilename, &bmpfilesize); 
						
						newfile_buffersize=(UINTN) bmpfilesize;
					
						status = gBS->AllocatePool(
							AllocateAnyPages,
							newfile_buffersize,
							(void**)&temp_buf); 
						
						if (status==EFI_SUCCESS){
							Print(L"allocate pool for file read successful!\n\n");
						}
						Print(L"BMP file width: %llu \n BMP file height: %llu \n", bmp->PixelWidth, bmp->PixelHeight); 
						//status=hostfile->GetInfo(hostfile, &file_info_guid, &bmpfileinfo_size, NULL);
						status=hostfile->Read(hostfile, &newfile_buffersize, temp_buf);
						UINT32 horiz_rez=gop_info->HorizontalResolution;
						UINT32 vert_rez=gop_info->VerticalResolution;
						if (status == EFI_SUCCESS){
							Print(L"file read with UEFISelfRep.efi successful! \n\n");
							status = gBS->AllocatePool(
								AllocateAnyPages,
								newfile_buffersize,
								(void**)&bmp_gop); 
							if (status == EFI_SUCCESS){
								Print(L"allocate pool for bmp_gop  successful!\n\n");
								status=TranslateBmpToGopBlt(temp_buf, newfile_buffersize, &bmp_gop, &gopbltsize, &bmp_pixelheight, &bmp_pixelwidth);
								status = gop->Blt(gop, bmp_gop, EfiBltBufferToVideo, 0, 0, 0, 0, bmp_pixelwidth, bmp_pixelheight, bmp_pixelwidth*sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
							}	
							//UINTN bmp_height= bmp_pixelheight / vert_rez / 2;
							//UINTN bmp_width= bmp_pixelwidth / horiz_rez / 2;
							status=TranslateBmpToGopBlt(temp_buf, newfile_buffersize, &bmp_gop, &gopbltsize, &bmp_pixelheight, &bmp_pixelwidth);
							if (status == EFI_SUCCESS){
								Print(L"Translate BMP File to GOP blt buffer successful! \n\n");
								if (bmp_pixelheight > vert_rez){
									Print(L"BMP image height: %d \n  pixelheight too large for screen resolution! :( \n\n", &bmp_pixelheight);
								}
								if (bmp_pixelwidth > horiz_rez){
									Print(L"BMP image widthi: %d \n pixelwidth too large for screen resolution! :( \n\n", &bmp_pixelwidth);
								}
								status = gop->Blt(gop, temp_buf, EfiBltBufferToVideo, 0, 0, 0, 0, bmp_pixelwidth, bmp_pixelheight, bmp_pixelwidth*sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
							} else if (status == EFI_BUFFER_TOO_SMALL){
								Print(L"Translate BMP File to GOP blt buffer not successful... trying again \n\n");
								status=TranslateBmpToGopBlt((void**)&temp_buf, newfile_buffersize, &bmp_gop, &gopbltsize, &bmp_pixelheight, &bmp_pixelwidth);

							} else if (status == RETURN_INVALID_PARAMETER){
								Print(L"params are fucked. Everything is horrible.\n");
							} else if (status == EFI_BUFFER_TOO_SMALL){
								Print(L"Everything is horrible.\n");
							}
;
						}
					}
					/*
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
					}*/
					status=targetfile->Close(targetfile);
					if (EFI_ERROR(status)){
						Print(L"error with close file call... \n\n");
					};
					//Print the first 256 chars from our input file to stdout as a check 				
					for (UINTN i=0; i < 0x100; i++){
						Print(L"%c", ((CHAR8 *)temp_buf)[i]);
					};
					//Print(L"Filename current UEFI app executable image: %s\n", ConvertDevicePathToText(devicefilepath ,FALSE,TRUE));
					gBS->FreePool(temp_buf);
					status=hostfile->Close(hostfile);
					rootvolume->Close(rootvolume);
				} else {
					Print(L" hmm open root volum unsuccessful... something got effed.");
				}
			
			} else {
				Print(L" hmm something got effed.");
			}
		}
	}	
	return status;		
}


EFI_STATUS
EFIAPI
GOPComplexUnload (
	EFI_HANDLE ImageHandle
	)
{
		Print(L"unloading GOP Complex");
		return EFI_SUCCESS;
}


