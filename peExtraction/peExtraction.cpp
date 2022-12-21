#include <windows.h>
#include <stdio.h>
//#include <objdump.h>
//#include "exedump.h"
//#include "extrnvar.h"
#include<iostream>
#include<winnt.h>

void dumpFile(LPCSTR fileName) {

	HANDLE hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Error opening file %s", fileName);
	}
	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		std::cout << "Error getting file size" << std::endl;
		return;
	}
	LPVOID fileBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
	if (fileBuffer == NULL) {
		std::cout << "Error allocating memory" << std::endl;
		return;
	}
	DWORD bytesRead;
	if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL)) {
		std::cout << "Error reading file" << std::endl;
		return;
	}
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cout << "Invalid DOS signature" << std::endl;
		return;
	}

	
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD)fileBuffer + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		std::cout << "Invalid NT signature" << std::endl;
		return;
	}

	
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		std::cout << "Section " << i << ": " << sectionHeader[i].Name << std::endl;
	}
	VirtualFree(fileBuffer, 0, MEM_RELEASE);
	CloseHandle(hFile);
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
		dumpFile(fileName);
	}
	catch (...)
	{
		std::cout << "Error" << std::endl;
	}
	std::cout << "Thank you for using the PE Extraction Tool" << std::endl
		<< "Press any key to exit" << std::endl;
	return 0;
}

