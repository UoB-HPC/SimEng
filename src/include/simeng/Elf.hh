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
  uint64_t alignment;
  char* content;
};

struct NoteEntry {
  uint32_t n_namesz;
  uint32_t n_descsz;
  uint32_t n_type;
  char* name;
  char* desc;
};

/** A processed Executable and Linkable Format (ELF) file. */
class Elf {
 public:
  Elf(std::string path);
  ~Elf();
  const void getContents(std::vector<ElfHeader>& contents) const;
  const void getNotes(std::vector<NoteEntry>& notes) const;
  bool isValid() const;
  uint64_t getEntryPoint() const;

 private:
  uint64_t entryPoint_;
  std::vector<ElfHeader> headers_;

  bool isValid_ = false;
  std::vector<NoteEntry> noteSegment_;
};

}  // namespace simeng
