#include "simeng/Elf.hh"

#include <cstring>
#include <fstream>
#include <iostream>

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
    file.read(reinterpret_cast<char*>(&(header.alignment)), fieldBytes);
    header.content = (char*)malloc(header.fileSize);

    // Read in contents where the program header points to
    file.seekg(header.offset);
    file.read(header.content, header.fileSize);

    // If the header belongs to a NOTE segment, read in contents
    if (header.type == 4) {
      uint64_t totalBytes = header.fileSize;
      uint64_t bytesRead = 0;
      file.seekg(header.offset);
      while (bytesRead < totalBytes) {
        // Read in each entry member and increment bytesRead by the size of the
        // member
        NoteEntry newEntry;
        // Size of entry name in bytes aligned to 4-byte boundary
        file.read(reinterpret_cast<char*>(&(newEntry.n_namesz)),
                  sizeof(newEntry.n_namesz));
        newEntry.n_namesz +=
            (newEntry.n_namesz % 4 == 0) ? 0 : (4 - (newEntry.n_namesz % 4));
        bytesRead += sizeof(newEntry.n_namesz);

        // Size of entry description in bytes aligned to 4-byte boundary
        file.read(reinterpret_cast<char*>(&(newEntry.n_descsz)),
                  sizeof(newEntry.n_descsz));
        newEntry.n_descsz +=
            (newEntry.n_descsz % 4 == 0) ? 0 : (4 - (newEntry.n_descsz % 4));
        bytesRead += sizeof(newEntry.n_descsz);

        // The type of the entry
        file.read(reinterpret_cast<char*>(&(newEntry.n_type)),
                  sizeof(newEntry.n_type));
        bytesRead += sizeof(newEntry.n_type);

        // The name of the entry
        newEntry.name = (char*)malloc(newEntry.n_namesz);
        file.read(newEntry.name, newEntry.n_namesz);
        bytesRead += newEntry.n_namesz;

        // The description of the entry
        newEntry.desc = (char*)malloc(newEntry.n_descsz);
        file.read(newEntry.desc, newEntry.n_descsz);
        bytesRead += newEntry.n_descsz;

        // Push back new entry
        noteSegment_.push_back(newEntry);
      }
    }
  }

  file.close();
}

Elf::~Elf() {}

const void Elf::getContents(std::vector<ElfHeader>& contents) const {
  contents = headers_;
}

const void Elf::getNotes(std::vector<NoteEntry>& notes) const {
  notes = noteSegment_;
}

uint64_t Elf::getEntryPoint() const { return entryPoint_; }
bool Elf::isValid() const { return isValid_; }

}  // namespace simeng
