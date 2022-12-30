#include <windows.h>
#include <stdio.h>
#include<iostream>
#include<winnt.h>

// return rva of section
DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
	if (rva == 0)
	{
		return (rva);
	}
	pSeh = psh;
	for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
			pSeh->Misc.VirtualSize)
		{
			break;
		}
		pSeh++;
	}
	return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}

void printHeaders(PIMAGE_OPTIONAL_HEADER pOptionalHeader) {
	printf("Address of entry point : %08X\n", pOptionalHeader->AddressOfEntryPoint);
	printf("Checksum : %08X\n", pOptionalHeader->CheckSum);
	printf("Image base from %08X to %08X\n", pOptionalHeader->ImageBase, pOptionalHeader->ImageBase + pOptionalHeader->SizeOfImage);
	printf("Image base : %08X \n", pOptionalHeader->ImageBase);
	printf("File alignment : %08X\n", pOptionalHeader->FileAlignment);
	printf("Size of image : %08X\n", pOptionalHeader->SizeOfImage);
	printf("\n");
}

void printSectionHeaders(PIMAGE_SECTION_HEADER pSectionHeader, PIMAGE_FILE_HEADER pFileHeader) {
	printf("=== Section Table ===\n");
	printf("Section name|\tVirtual size|\tVirtual address|\tRaw size|\tRaw address|\tCharacteristics|\n");
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{

		printf("%s\t%15X\t%15X\t%22X\t%19X\t%15X\n", pSectionHeader[i].Name
			, pSectionHeader[i].Misc.VirtualSize
			, pSectionHeader[i].VirtualAddress
			, pSectionHeader[i].SizeOfRawData
			, pSectionHeader[i].PointerToRawData
			, pSectionHeader[i].Characteristics);
	}
	printf("\n");
}

void printImportTable(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, PIMAGE_SECTION_HEADER pSectionHeader, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_NT_HEADERS pNTHeader, PIMAGE_OPTIONAL_HEADER pOptionalHeader, LPVOID lpFileBase) {
	if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)/*if size of the table is 0 - Import Table does not exist */
	{
		LPSTR libname[256]{};
		size_t i = 0;
		// Walk until you reached an empty PIMAGE_EXPORT_DIRECTORY
		printf("=== Import Library Name ===\n");
		while (pImportDescriptor->Name != NULL)
		{
			//Get the name of each DLL
			libname[i] = (PCHAR)((DWORD_PTR)lpFileBase + Rva2Offset(pImportDescriptor->Name, pSectionHeader, pNTHeader));
			printf("\t%s\n", libname[i]);
			pImportDescriptor++; //advance to next PIMAGE_EXPORT_DIRECTORY
			i++;

		}
	}
	else
	{
		printf("No Import Table!\n");
	}
	printf("\n");
}

void printExportTable(PIMAGE_EXPORT_DIRECTORY pExportDirectory, PIMAGE_SECTION_HEADER pSectionHeader, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_NT_HEADERS pNTHeader, PIMAGE_OPTIONAL_HEADER pOptionalHeader, LPVOID lpFileBase) {
	if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)/*if size of the table is 0 - Export Table does not exist */
	{
		LPSTR libname[256]{};
		size_t i = 0;
		// Walk until you reached an empty IMAGE_IMPORT_DESCRIPTOR
		printf("=== Export Library Name ===\n");
		while (pExportDirectory->Name != NULL)
		{
			//Get the name of each DLL
			libname[i] = (PCHAR)((DWORD_PTR)lpFileBase + Rva2Offset(pExportDirectory->Name, pSectionHeader, pNTHeader));
			printf("\t%s\n", libname[i]);
			pExportDirectory++; //advance to next IMAGE_IMPORT_DESCRIPTOR
			i++;

		}
	}
	else
	{
		printf("No Export Table!\n");
	}
}

// dump PE file headers and sections
// flow open & read file -> create mapping object -> map view of file -> get pointers to each criterias -> dump headers and sections
bool DumpPEHeader(LPCSTR filename)
{
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID lpFileBase;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNTHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
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
		printHeaders(pOptionalHeader);
		
		// print the file sections
		printSectionHeaders(pSectionHeader, pFileHeader);
		
		// print the file import table
		pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpFileBase + \
			Rva2Offset(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSectionHeader, pNTHeader));
		printImportTable(pImportDescriptor, pSectionHeader, pNTHeader, pNTHeader, pOptionalHeader, lpFileBase);
		
		// print the file export table
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)lpFileBase + \
			Rva2Offset(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, pSectionHeader, pNTHeader));
		printExportTable(pExportDirectory, pSectionHeader, pNTHeader, pNTHeader, pOptionalHeader, lpFileBase);
		return true;
	}
	catch (LPCSTR msg) {
		printf("Error: %s\n", msg);
		return false;
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
		//LPCSTR fileName = "C:\\Windows\\notepad.exe";
		std::cout << "Dump of file " << fileName << std::endl;
		DumpPEHeader(fileName);
	}
	catch (LPCSTR msg) {
		printf("Error: %s (%d)\r ", msg, GetLastError());
	}
	return 0;
}