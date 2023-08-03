#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

EFI_STATUS
EFIAPI
UefiMain (
	IN EFI_HANDLE			ImageHandle,
	IN EFI_SYSTEM_TABLE		*SystemTable
	)

//EFI_BOOT_SERVICES *bootservicestest = (SystemTable->BootServices);
{
	EFI_BOOT_SERVICES *gBS=(SystemTable->BootServices);;
	//void *conduit = &(SystemTable->BootServices);
	//char const(*bootserviceaddress)(void)=conduit;
	//unsigned int *bst_adr=(unsigned char*)&bootserviceaddress;
	//CHAR16 *bst_adr=&bootserviceaddress;
	SystemTable->ConOut->OutputString(SystemTable->ConOut, L"hello from the other side\n");
	Print(L"Boot Services Table address is: %p", &gBS);	
	//SystemTable->ConOut->OutputString(SystemTable->ConOut,L"%s", &bootservicestest);
	/*for(int i=0; i < sizeof bootserviceaddress; i++){
		SystemTable->ConOut->OutputString(SystemTable->ConOut, bst_adr[i]);
	}*/
	return EFI_SUCCESS;
}
