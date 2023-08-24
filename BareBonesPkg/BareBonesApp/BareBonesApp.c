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
	EFI_LOCATE_PROTOCOL locateProtocolHook=(gBS->LocateProtocol);
	
	//void *conduit = &(SystemTable->BootServices);
	SystemTable->ConOut->OutputString(SystemTable->ConOut, L"hello from the other side\n");
	Print(L"Boot Services Table address is: %p \n\n", &gBS);	
	Print(L"Boot Services LocateHandleBuffer() function pointer  address is: %p \n\n", &locateProtocolHook);	
	//SystemTable->ConOut->OutputString(SystemTable->ConOut,L"%s", &bootservicestest);
	/*for(int i=0; i < sizeof bootserviceaddress; i++){
		SystemTable->ConOut->OutputString(SystemTable->ConOut, bst_adr[i]);
	}*/
	return EFI_SUCCESS;
}
