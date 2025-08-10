#include <iostream>
#include <functional>
#include <filesystem>
#include <fstream>
#include "AES.h"
#include "Timer.h"

void Help();
void RemovePadding(std::vector<uint8_t>& buffer);

int main(int argc, char* argv[])
{
	if (argc < 2 || strcmp(argv[1], "-help") == 0 || strcmp(argv[1], "--help") == 0)
	{
		Help();
		return 0;
	}

	std::string extension = ".dec";

	if (argc >= 3)
	{
		for (int i = 2; i < argc; ++i)
		{
			if (strcmp(argv[i], "-r") == 0)
			{
				extension = "";
			}
			else if (strcmp(argv[i], "-e") == 0)
			{
				++i;
				if (i == argc)
				{
					std::cout << "No extension provided." << std::endl;
					return 1;
				}
				if (argv[i][0] == '.')
				{
					extension = argv[i];
				}
				else
				{
					extension = std::string(".") + argv[i];
				}
			}
		}
	}

	std::hash<std::string> hasher;
	std::vector<uint8_t> key;
	key.resize(16);

	std::ifstream keyFile("key.txt");
	if (!keyFile.is_open())
	{
		keyFile.open("password.txt");
		if (!keyFile.is_open())
		{
			keyFile.open("pass.txt");
			if (!keyFile.is_open())
			{
				std::cout << "Could not find or open key.txt" << std::endl;
				return 1;
			}
		}
	}

	std::cout << "Reading password" << std::endl;

	std::string password;

	std::getline(keyFile, password);
	if (password.empty())
	{
		std::cout << "key.txt was empty" << std::endl;
		return 1;
	}
	uint64_t p0 = hasher(password.substr(0, password.size() / 2));
	uint64_t p1 = hasher(password.substr(password.size() / 2));

	memcpy_s(key.data(), sizeof(uint64_t), &p0, sizeof(uint64_t));
	memcpy_s(key.data() + sizeof(uint64_t), sizeof(uint64_t), &p1, sizeof(uint64_t));

	std::filesystem::path filePath(argv[1]);

	std::ifstream fileIn(filePath, std::ios::binary | std::ios::ate);
	if (!fileIn.is_open())
	{
		std::cout << "Could not open file: " << filePath << std::endl;
		return 1;
	}

	size_t size = fileIn.tellg();
	fileIn.seekg(0, std::ios::beg);
	size_t blocks = size / 16;

	std::vector<uint8_t> dataBuffer;
	dataBuffer.resize(16);

	if (extension.empty())
	{
		if (!filePath.has_extension())
		{
			std::cout << "Cannot remove extension. \"" << filePath << "\" would be overwritten." << std::endl;
			return 1;
		}
		filePath = filePath.parent_path() / filePath.stem();
	}
	else
	{
		if (extension != ".dec")
		{
			filePath = filePath.parent_path() / filePath.stem();
		}
		filePath += extension;
	}

	std::ofstream fileOut(filePath, std::ios::binary | std::ios::trunc);
	if (!fileOut.is_open())
	{
		std::cout << "Could not create encrypted file" << std::endl;
		return 1;
	}

	float invTotal = 1.f / blocks;
	xe::Timer timer;

	AES aes(AESKeyLength::AES_128);
	for (size_t i = 0; i < blocks - 1; ++i)
	{
		fileIn.read((char*)dataBuffer.data(), 16);
		dataBuffer = aes.DecryptECB(dataBuffer, key);
		fileOut.write((char*)dataBuffer.data(), dataBuffer.size());

		if (timer.GetElapsed() >= 1.f)
		{
			timer.Reset();
			float progress = ((int)(i * invTotal * 10000)) * .01f;
			std::cout << "\rProgress: " << progress << "%              ";
		}
	}

	fileIn.read((char*)dataBuffer.data(), 16);
	dataBuffer = aes.DecryptECB(dataBuffer, key);
	RemovePadding(dataBuffer);
	fileOut.write((char*)dataBuffer.data(), dataBuffer.size());
	std::cout << "\nDone!" << std::endl;

	return 0;
}

void Help()
{
	std::cout << "Usage: dec <filepath> | NOTE: key.txt must be present in working directory" << std::endl;
	std::cout << "    Flags" << std::endl;
	std::cout << "    > -e <ext|.ext>   | replaces existing extension with one provided" << std::endl;
	std::cout << "    > -r              | removes existing extension" << std::endl;
}

void RemovePadding(std::vector<uint8_t>& buffer)
{
	uint8_t last = buffer.back();

	if (last != 0 && last < 16)
	{
		bool isPadding = true;
		for (size_t i = buffer.size() - last; i < buffer.size() - 1; ++i)
		{
			if (buffer[i] != last)
			{
				isPadding = false;
				break;
			}
		}
		if (isPadding)
		{
			buffer.erase(buffer.begin() + buffer.size() - last, buffer.end());
		}
	}
}
