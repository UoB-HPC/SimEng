#pragma once

#include <string>
#include <vector>
#include <unordered_map>

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

typedef struct {
  unsigned char e_ident[16];
  uint16_t      e_type;
  uint16_t      e_machine;
  uint32_t      e_version;
  uint32_t      e_entry;
  uint32_t      e_phoff;
  uint32_t      e_shoff;
  uint32_t      e_flags;
  uint16_t      e_ehsize;
  uint16_t      e_phentsize;
  uint16_t      e_phnum;
  uint16_t      e_shentsize;
  uint16_t      e_shnum;
  uint16_t      e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    uint32_t   p_type;
    uint32_t   p_offset;
    uint32_t   p_vaddr;
    uint32_t   p_paddr;
    uint32_t   p_filesz;
    uint32_t   p_memsz;
    uint32_t   p_flags;
    uint32_t   p_align;
} Elf32_Phdr;

typedef struct {
  uint32_t   sh_name;
  uint32_t   sh_type;
  uint32_t   sh_flags;
  uint32_t   sh_addr;
  uint32_t   sh_offset;
  uint32_t   sh_size;
  uint32_t   sh_link;
  uint32_t   sh_info;
  uint32_t   sh_addralign;
  uint32_t   sh_entsize;
} Elf32_Shdr;

typedef struct {
    uint32_t      st_name;
    uint32_t      st_value;
    uint32_t      st_size;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t      st_shndx;
} Elf32_Sym;

enum ElfPhType {
  PT_NULL,
  PT_LOAD
};

enum ElfShType {
  SHT_NULL,
  SHT_PROGBITS,
  SHT_SYMTAB,
  SHT_STRTAB
};

/** A processed Executable and Linkable Format (ELF) file. */
class Elf {
  public:
    Elf(std::string path, char** imagePointer, std::unordered_map<std::string, uint64_t>& symbols);
    ~Elf();
    uint64_t  getProcessImageSize() const;
    bool      isValid() const;
    uint64_t  getEntryPoint() const;

  private:
    uint64_t  entryPoint_;
    std::vector<ElfHeader> headers_;
    uint32_t  entryPoint32_;
    std::vector<Elf32Header> headers32_;
    bool      isValid_ = false;
    uint64_t  processImageSize_;
    bool      mode32bit_;
};

}  // namespace simeng
