#include <iostream>
#include <functional>
#include <filesystem>
#include <fstream>
#include "AES.h"
#include "Timer.h"

#include <future>

void Help();
void RemovePadding(std::vector<uint8_t>& buffer);
std::vector<uint8_t> DecryptAsync(size_t start, size_t length, const std::filesystem::path& path, const std::vector<uint8_t>& key);

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

	std::filesystem::path inPath(argv[1]);

	std::ifstream fileIn(inPath, std::ios::binary | std::ios::ate);
	if (!fileIn.is_open())
	{
		std::cout << "Could not open file: " << inPath << std::endl;
		return 1;
	}

	size_t size = fileIn.tellg();
	fileIn.close();
	size_t blocks = size / 16;

	std::filesystem::path outPath = inPath;
	if (extension.empty())
	{
		if (!outPath.has_extension())
		{
			std::cout << "Cannot remove extension. \"" << outPath << "\" would be overwritten." << std::endl;
			return 1;
		}
		outPath = outPath.parent_path() / outPath.stem();
	}
	else
	{
		if (extension != ".dec")
		{
			outPath = outPath.parent_path() / outPath.stem();
		}
		outPath += extension;
	}

	std::ofstream fileOut(outPath, std::ios::binary | std::ios::trunc);
	if (!fileOut.is_open())
	{
		std::cout << "Could not create encrypted file" << std::endl;
		return 1;
	}

	size_t blocksPerThread = 100000;
	int threadCount = std::thread::hardware_concurrency();

	std::cout << "Thread Pool Size: " << threadCount << std::endl;

	float invTotal = 1.f / blocks;
	xe::Timer timer;

	for (size_t i = 0; i < blocks - 1;)
	{
		std::vector<std::future<std::vector<uint8_t>>> asyncProcesses;
		while (i < blocks - 1 && asyncProcesses.size() < threadCount)
		{
			size_t count = (i + blocksPerThread >= blocks - 1) ? blocks - 1 - i : blocksPerThread;
			std::future<std::vector<uint8_t>> f = std::async(std::launch::async, DecryptAsync, i, count, inPath, key);
			i += count;
			asyncProcesses.push_back(std::move(f));
		}

		for (std::future<std::vector<uint8_t>>& result : asyncProcesses)
		{
			std::vector<uint8_t> buffer = result.get();
			fileOut.write((char*)buffer.data(), buffer.size());
		}

		if (timer.GetElapsed() >= 1.f)
		{
			timer.Reset();
			float progress = ((int)(i * invTotal * 10000)) * .01f;
			std::cout << "\rProgress: " << progress << "%              ";
		}
	}

	std::vector<uint8_t> buffer = DecryptAsync(blocks - 1, 1, inPath, key);
	RemovePadding(buffer);
	fileOut.write((char*)buffer.data(), buffer.size());

	std::cout << "\nDone!" << std::endl;

	return 0;
}

void Help()
{
	std::cout << "Usage: dec-mt <filepath> | NOTE: key.txt must be present in working directory" << std::endl;
	std::cout << "    Flags" << std::endl;
	std::cout << "    > -e <ext|.ext>      | replaces existing extension with one provided" << std::endl;
	std::cout << "    > -r                 | removes existing extension" << std::endl;
}

std::vector<uint8_t> DecryptAsync(size_t start, size_t length, const std::filesystem::path& path,  const std::vector<uint8_t>& key)
{
	std::vector<uint8_t> result(length * 16);
	std::ifstream file(path, std::ios::binary);
	file.seekg(start * 16);

	file.read((char*)result.data(), result.size());
	AES aes(AESKeyLength::AES_128);
	result = aes.DecryptECB(result, key);

	return result;
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
