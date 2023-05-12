#pragma once

#include <string>
#include <vector>

#include "simeng/span.hh"

namespace simeng {

namespace ElfBitFormat {
const char Format32 = 1;
const char Format64 = 2;
}  // namespace ElfBitFormat

struct ElfHeader {
  uint32_t type;
  uint64_t offset;
  uint64_t virtualAddress;
  uint64_t physicalAddress;
  uint64_t fileSize;
  uint64_t memorySize;
};

struct Elf32Header {
  uint32_t type;
  uint32_t offset;
  uint32_t virtualAddress;
  uint32_t physicalAddress;
  uint32_t fileSize;
  uint32_t memorySize;
};

/** A processed Executable and Linkable Format (ELF) file. */
class Elf {
 public:
  Elf(std::string path, char** imagePointer);
  ~Elf();
  uint64_t getProcessImageSize() const;
  bool isValid() const;
  uint64_t getEntryPoint() const;

 private:
  uint64_t entryPoint_;
  std::vector<ElfHeader> headers_;
  uint32_t entryPoint32_;
  std::vector<Elf32Header> headers32_;
  bool isValid_ = false;
  uint64_t processImageSize_;
  bool mode32bit_;
};

}  // namespace simeng
