# enc - Readme

## Disclaimer
These tools were developed as an exercise. DO NOT use these tools to encrypt sensitive data.

## Description
A suit of command line tools for encrypting and decrypting files using AES encryption. tools are as follows:

- `enc`: Encypt file
- `dec`: Decrypt file
- `enc-mt`: Encypt file, multithreaded
- `dec-mt`: Decrypt file, multithreaded

### Flags
|Flag           |Description                      |
|---------------|---------------------------------|
|`--help`       |Show help message                |
|`-e <ext/.ext>`|Set file extension on new file   |
|`-r`           |Remove file extension on new file|

NOTE: A text file containing your password must be in the working directory. The file must be named either `key.txt`, `pass.txt` or `password.txt`.

Since these tools use `std::hash` to hash passwords, resulting hash values may change between different platforms and compilers resulting in encypted files not working cross-platform.

## Example

### Encrypting
Encrypting a file named `myFile.jpg` and removing extension (resulting file: `myFile`):

`enc myFile.jpg -r`

### Decrypting
Decrypting a file named `myFile` and added the extension `.jpg` (resulting file: `myFile.jpg`):

`dec myFile -e jpg`

### Multithreading

Multithreading versions are the same as above, just replace `enc` with `enc-mt` and `dec` with `dec-mt`.

## Repository

[SergeyBel/AES](https://github.com/SergeyBel/AES) is required for this repository. Source code included.

This repository uses the the [premake5](https://premake.github.io/) build system. Run `generate-vs2022.bat` to generate a Visual Studio 2022 solution.