#pragma once

#include <string>
#include <vector>

#include "simeng/span.hh"

namespace simeng {

namespace ElfBitFormat {
const char Format32 = 1;
const char Format64 = 2;
}  // namespace ElfBitFormat

struct Elf64_Phdr {
  uint32_t p_type;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
};

/** A processed Executable and Linkable Format (ELF) file. */
class Elf {
 public:
  Elf(std::string path, char** imagePointer);
  ~Elf();
  uint64_t getProcessImageSize() const;
  bool isValid() const;
  uint64_t getEntryPoint() const;
  uint64_t getPhdrTableAddress() const;
  uint64_t getPHENT() const;
  uint64_t getPHNUM() const;

 private:
  uint64_t entryPoint_;
  std::vector<Elf64_Phdr> pheaders_;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint64_t phdrTableAddress_ = 0;
  bool isValid_ = false;
  uint64_t processImageSize_;
};

}  // namespace simeng
