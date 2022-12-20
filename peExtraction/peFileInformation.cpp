#include<iostream>
#include<Windows.h>
#include<winnt.h>

#include<ImageHlp.h>


typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, * PIMAGE_NT_HEADERS;

class peFileInformation
{
public:
	// get AddressOfEntryPoint from PE header

	// calculate PE file checksum 






	
};