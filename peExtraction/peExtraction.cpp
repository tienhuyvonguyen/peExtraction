#include <iostream>
#include <string>
#include <fstream>

void showMenu();
std::string get_input_filename();
std::string get_file_contents(std::string const& infile);
int userInput();

int main()
{
	std::cout << "Welcome to the PE Extraction Tool" << std::endl;
	std::cout << "Please choose from the following options" << std::endl;
	std::string input_filename = get_input_filename();
	std::string content = get_file_contents(input_filename);
	std::cout << content << std::endl;
	try
	{
		showMenu();
		int choice = userInput();
		while (choice != -1)
		{
			switch (choice)
			{
			case 1:
				std::cout << "You chose 1" << std::endl;
				break;
			case 2:
				std::cout << "You chose 2" << std::endl;
				break;
			case 3:
				std::cout << "You chose 3" << std::endl;
				break;
			case 4:
				std::cout << "You chose 4" << std::endl;
				break;
			case 5:
				std::cout << "You chose 5" << std::endl;
				break;
			case 6:
				std::cout << "You chose 6" << std::endl;
				break;
			case 7:
				std::cout << "You chose 7" << std::endl;
				break;
			case 8:
				std::cout << "You chose 8" << std::endl;
				break;
			case 9:
				std::cout << "You chose 9" << std::endl;
				break;
			case 10:
				std::cout << "You chose 10" << std::endl;
				break;
			default:
				std::cout << "Invalid choice" << std::endl;
				break;
			}
		}
	}
	catch (const std::exception&)
	{
		std::cout << "Error" << std::endl;
	}
	std::cout << "Thank you for using the PE Extraction Tool" << std::endl
		<< "Press any key to exit" << std::endl;
	return 0;
}

// show menu function 
void showMenu()
{
	std::cout << "=== PE File Information ===" << std::endl;
	std::cout << "1. Point to Entry Point" << std::endl;
	std::cout << "2. CheckSum" << std::endl;
	std::cout << "3. Imagebase" << std::endl;
	std::cout << "4. File Aligment" << std::endl;
	std::cout << "5. Size of image" << std::endl;
	std::cout << "" << std::endl;
	std::cout << "=== PE File Section Information ===" << std::endl;
	std::cout << "6. Characteristics" << std::endl;
	std::cout << "7. Raw Address" << std::endl;
	std::cout << "8. Raw Size" << std::endl;
	std::cout << "9. Virtual Address" << std::endl;
	std::cout << "10. Virtual Size" << std::endl;
}

int userInput() {
	int choice = 0;
	std::cout << "Enter your choice: ";
	std::cin >> choice;
	return choice;
}

std::string get_file_contents(std::string const& infile)
{
	std::ifstream inf(infile);
	std::string contents;
	int c;
	while ((c = inf.get()) != EOF)
	{
		contents += c;
	}
	return contents;
}

std::string get_input_filename()
{
	std::string filename;
	std::cout << "Please enter the name of the input file." << std::endl;
	std::cout << "Filename: ";
	std::cin >> filename;
	return filename;
}