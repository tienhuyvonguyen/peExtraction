# peExtraction
Tested with notepad.exe.

- [x]  - PointerToEntryPoint
- [x]  - CheckSum
- [x]  - ImageBase check
- [x]  - FileAlignment
- [x]  - SizeOfImage

Information about all sections of the file:

- [x]  - Name
- [x]  - Characteristics - an executable or a DLL
- [x]  - RawAddress
- [x]  - RawSize
- [x]  - VirtualAddress
- [x]  - VirtualSize
- imports and exports

USAGE: 
- With source: 
  - Run compile.bat 
  - Use peExtraction.exe <PE file>
- With executable:
  - Run peExtraction.exe <PE file>
