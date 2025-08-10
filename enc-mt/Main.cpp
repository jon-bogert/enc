#include <iostream>
#include <functional>
#include <filesystem>
#include <fstream>
#include <thread>
#include <future>
#include "AES.h"
#include "Timer.h"

void Help();
void AddPadding(std::vector<uint8_t>& buffer);
std::vector<uint8_t> EncryptAsync(size_t start, size_t length, const std::filesystem::path& path, const std::vector<uint8_t>& key);

int main (int argc, char* argv[])
{
    if (argc < 2 || strcmp(argv[1], "-help") == 0 || strcmp(argv[1], "--help") == 0)
    {
        Help();
        return 0;
    }

    std::string extension = ".enc";

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
        std::cout << "key file was empty" << std::endl;
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
    size_t fullBlocks = size / 16;
    size_t remainder = size % 16;

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
        if (extension != ".enc")
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

    float invTotal = 1.f / fullBlocks;
    xe::Timer timer;

    for (size_t i = 0; i < fullBlocks;)
    {
        std::vector<std::future<std::vector<uint8_t>>> asyncProcesses;
        while (i < fullBlocks && asyncProcesses.size() < threadCount)
        {
            size_t count = (i + blocksPerThread >= fullBlocks) ? fullBlocks - i : blocksPerThread;
            std::future<std::vector<uint8_t>> f = std::async(std::launch::async, EncryptAsync, i, count, inPath, key);
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

    if (remainder != 0)
    {
        std::vector<uint8_t> buffer;
        buffer.reserve(16);
        buffer.resize(remainder);

        std::ifstream file(inPath, std::ios::binary);
        file.seekg(size - remainder);
        file.read((char*)buffer.data(), buffer.size());
        AddPadding(buffer);

        AES aes(AESKeyLength::AES_128);
        buffer = aes.EncryptECB(buffer, key);

        fileOut.write((char*)buffer.data(), buffer.size());
    }
    
    std::cout << "\nDone!" << std::endl;

    return 0;
}

void Help()
{
    std::cout << "Usage: enc-mt <filepath> | NOTE: key.txt must be present in working directory" << std::endl;
    std::cout << "    Flags" << std::endl;
    std::cout << "    > -e <ext|.ext>      | replaces existing extension with one provided" << std::endl;
    std::cout << "    > -r                 | removes existing extension" << std::endl;
}

std::vector<uint8_t> EncryptAsync(size_t start, size_t length, const std::filesystem::path& path, const std::vector<uint8_t>& key)
{
    std::vector<uint8_t> result(length * 16);
    std::ifstream file(path, std::ios::binary);
    file.seekg(start * 16);

    file.read((char*)result.data(), result.size());
    AES aes(AESKeyLength::AES_128);
    result = aes.EncryptECB(result, key);

    return result;
}

void AddPadding(std::vector<uint8_t>& buffer)
{
    uint8_t padding = static_cast<uint8_t>(16 - (buffer.size() % 16));
    if (padding != 16)
    {
        for (uint8_t i = 0; i < padding; ++i)
        {
            buffer.push_back(padding);
        }
    }
}
