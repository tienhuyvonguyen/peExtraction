#include <iostream>
#include <string>
#include <winnt.h>



int main(int argc, char* argv[])
{
	try
	{
		std::string path = argv[1];
		std::cout << path << std::endl;
	}
	catch (const std::exception&)
	{
		std::cout << "Error" << std::endl;
	}
	std::cout << "Thank you for using the PE Extraction Tool" << std::endl
		<< "Press any key to exit" << std::endl;
	return 0;
}

