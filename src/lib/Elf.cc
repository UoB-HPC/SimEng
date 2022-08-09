#include "simeng/Elf.hh"

#include <cstring>
#include <fstream>
#include <iostream>

namespace simeng {

/**
 * Here we extract information from an ELF binary
 * 32-bit and 64-bit architectures have variance in the structs
 * used to define the structure of an ELF binary. All information
 * presente in this documentation has been referenced from:
 * https://man7.org/linux/man-pages/man5/elf.5.html
 */

Elf::Elf(std::string path) {
  std::ifstream file(path, std::ios::binary);

  if (!file.is_open()) {
    return;
  }

  /**
   * Using the reference mentioned above, the ELF header
   * is defined by the elf64_hdr struct for 64-bit systems.
   * `elf64_hdr->e_ident` is an array of bytes which specifies
   * how to interpret the ELF file, independent of the 
   * processor or the file's remaining contents. All ELF
   * files start with the ELF header.
   */

  /** 
   * First four bytes of the ELF header represent the ELF Magic Number. 
   */
  char elfMagic[4] = {0x7f, 'E', 'L', 'F'};
  char fileMagic[4];
  file.read(fileMagic, 4);
  if (std::memcmp(elfMagic, fileMagic, sizeof(elfMagic))) {
    return;
  }

  /**
   * The fifth byte of the ELF Header identifies the architecture
   * of the ELF binary.
   */

  // Check whether this is a 32- or 64-bit executable
  char bitFormat;
  file.read(&bitFormat, sizeof(bitFormat));
  if (bitFormat != ElfBitFormat::Format64) {
    return;
  }

  isValid_ = true;
  // Here we seek to the entry point of the file. 
  // The information in between is discarded 
  /**
   * The 24th byte of the ELF header representsa 64-bit 
   * virtual address to which the system first transfers
   * control, thus starting the process.
   * In `elf64_hdr` struct it is defined as `Elf64_Addr e_entry`.
   */
  file.seekg(0x18); 
  // Entry point
  file.read(reinterpret_cast<char*>(&entryPoint_), sizeof(entryPoint_));

  // Here we seek to the byte representing the start of the
  //  header offset table.
  /**
   * The 32nd byte of the ELF Header holds the 64-bit offset of 
   * the program header table in the ELF file.
   * In `elf64_hdr` struct it is defined as `Elf64_Addr e_phoff`.
   */
  uint64_t headerOffset;
  file.read(reinterpret_cast<char*>(&headerOffset), sizeof(headerOffset));

  // Header table info
  file.seekg(0x36);
  uint16_t headerEntrySize;
  file.read(reinterpret_cast<char*>(&headerEntrySize), sizeof(headerEntrySize));
  uint16_t headerEntries;
  file.read(reinterpret_cast<char*>(&headerEntries), sizeof(headerEntries));

  headers_.resize(headerEntries);
  uint64_t lss = 0;
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
      lss += header.fileSize;
      file.read(processImage_ + header.virtualAddress, header.fileSize);
    }
  }

  std::cout << "Process Image Size: " << processImageSize_ << std::endl;
  std::cout << "Actual Load Segment Size: " << lss << std::endl;

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
