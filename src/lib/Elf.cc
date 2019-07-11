#include "simeng/Elf.hh"

#include <cstring>
#include <fstream>

namespace simeng {

Elf::Elf(std::string path) {
  std::ifstream file(path, std::ios::binary);

  if (!file.is_open()) {
    return;
  }

  // Check file's magic number
  char elfMagic[4] = {0x7f, 'E', 'L', 'F'};
  char fileMagic[4];
  file.read(fileMagic, 4);
  if (std::memcmp(elfMagic, fileMagic, sizeof(elfMagic))) {
    return;
  }

  // Check whether this is a 32- or 64-bit executable
  char bitFormat;
  file.read(&bitFormat, sizeof(bitFormat));
  if (bitFormat != ElfBitFormat::Format64) {
    return;
  }

  isValid_ = true;

  file.seekg(0x18);
  // Entry point
  file.read(reinterpret_cast<char*>(&entryPoint_), sizeof(entryPoint_));

  // Header table offset
  uint64_t headerOffset;
  file.read(reinterpret_cast<char*>(&headerOffset), sizeof(headerOffset));

  // Header table info
  file.seekg(0x36);
  uint16_t headerEntrySize;
  file.read(reinterpret_cast<char*>(&headerEntrySize), sizeof(headerEntrySize));
  uint16_t headerEntries;
  file.read(reinterpret_cast<char*>(&headerEntries), sizeof(headerEntries));

  headers_.resize(headerEntries);
  processImageSize_ = 0;
  // Extract headers
  for (size_t i = 0; i < headerEntries; i++) {
    file.seekg(headerOffset + (i * headerEntrySize));
    auto& header = headers_[i];

    // Each address-related field is 8 bytes in a 64-bit ELF file
    const int fieldBytes = 8;
    file.read(reinterpret_cast<char*>(&(header.type)), sizeof(header.type));
    file.seekg(4, std::ios::cur);  // Skip flags
    file.read(reinterpret_cast<char*>(&(header.offset)), fieldBytes);
    file.read(reinterpret_cast<char*>(&(header.virtualAddress)), fieldBytes);
    file.read(reinterpret_cast<char*>(&(header.physicalAddress)), fieldBytes);
    file.read(reinterpret_cast<char*>(&(header.fileSize)), fieldBytes);
    file.read(reinterpret_cast<char*>(&(header.memorySize)), fieldBytes);

    if (header.virtualAddress + header.memorySize > processImageSize_) {
      processImageSize_ = header.virtualAddress + header.memorySize;
    }
  }

  processImage_ = new char[processImageSize_];

  // Process headers; only observe LOAD sections for this basic implementation
  for (const auto& header : headers_) {
    if (header.type == 1) {  // LOAD
      file.seekg(header.offset);
      // Read `fileSize` bytes from `file` into the appropriate place in process
      // memory
      file.read(processImage_ + header.virtualAddress, header.fileSize);
    }
  }

  file.close();
}

Elf::~Elf() {
  if (isValid_) {
    delete[] processImage_;
  }
}

const span<char> Elf::getProcessImage() const {
  return {processImage_, processImageSize_};
}

uint64_t Elf::getEntryPoint() const { return entryPoint_; }
bool Elf::isValid() const { return isValid_; }

}  // namespace simeng
