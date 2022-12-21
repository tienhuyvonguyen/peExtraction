#include <windows.h>
#include <stdio.h>
#include<iostream>
#include<winnt.h>

// dump and print the PE header and section table of the specified file 
void DumpPEHeader(LPCSTR filename)
{
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID lpFileBase;

	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNTHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;

	try {
		// open the file for reading
		hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			throw "CreateFile() failed";

		// create a file mapping object
		hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hFileMapping == NULL)
			throw "CreateFileMapping() failed";

		// map a view of the file
		lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		if (lpFileBase == NULL)
			throw "MapViewOfFile() failed";

		// get a pointer to the DOS header
		pDosHeader = (PIMAGE_DOS_HEADER)lpFileBase;

		// check the magic number
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			throw "Not a valid executable file";

		// get a pointer to the NT (PE) header
		pNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)lpFileBase + pDosHeader->e_lfanew);

		// check the signature
		if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
			throw "Not a valid PE file";

		// get pointers to the sections
		pFileHeader = &pNTHeader->FileHeader;
		pOptionalHeader = &pNTHeader->OptionalHeader;
		pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);

		// print the file header
		printf("Address of entry point : %08X\n", pOptionalHeader->AddressOfEntryPoint);
		printf("Checksum : %08X\n", pOptionalHeader->CheckSum);
		printf("Image base from %08X to %08X\n", pOptionalHeader->ImageBase, pOptionalHeader->ImageBase + pOptionalHeader->SizeOfImage);
		printf("Image base : %08X \n", pOptionalHeader->ImageBase);
		printf("File alignment : %08X\n", pOptionalHeader->FileAlignment);
		printf("Size of image : %08X\n", pOptionalHeader->SizeOfImage);
		// print the file sections
		printf("Section name|\tVirtual size\tVirtual address\tRaw size\tRaw address\tCharacteristics\n");
		for (int i = 0; i < pFileHeader->NumberOfSections; i++)
		{
			printf("%s\t%15X\t%15X\t%15X\t%15X\t%15X\n", pSectionHeader[i].Name
				, pSectionHeader[i].Misc.VirtualSize
				, pSectionHeader[i].VirtualAddress
				, pSectionHeader[i].SizeOfRawData
				, pSectionHeader[i].PointerToRawData
				, pSectionHeader[i].Characteristics);
		}
	}
	catch (LPCSTR msg) {
		printf("Error: %s (%d)\r ", msg, GetLastError());
	}
}
int main(int argc, char* argv[])
{
	try
	{
		if (argc < 2)
		{
			std::cout << "Usage: peExtraction.exe <filename>" << std::endl;
			return 0;
		}

		LPCSTR fileName = argv[1];
		std::cout << "Dumping file " << fileName << std::endl;
		DumpPEHeader(fileName);
	}
	catch (LPCSTR msg) {
		printf("Error: %s (%d)\r ", msg, GetLastError());
	}
	return 0;
}

