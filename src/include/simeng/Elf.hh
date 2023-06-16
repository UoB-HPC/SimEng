#pragma once

#include <array>
#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "simeng/span.hh"

namespace simeng {

namespace ElfBitFormat {
const char Format32 = 1;
const char Format64 = 2;
}  // namespace ElfBitFormat

// Elf64_Phdr as described in the elf man page. Only contains SimEng relevant
// information

// An executable or shared object file's program header table is an array of
// structures, each describing a segment or other information the system needs
// to prepare the program for execution.  An object file segment contains one or
// more sections. Program headers are meaningful only for executable and shared
// object files.  A file specifies its own program header size with the ELF
// header's e_phentsize and the number of headers with e_phnum members.  The ELF
// program header is described by the type Elf32_Phdr or Elf64_Phdr depending on
// the architecture

typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Offset;

struct Elf64_Phdr {
  // Indicates what kind of segment this array element describes or
  // how to interpret the array element's information
  uint32_t p_type = 0;
  uint32_t p_flags = 0;
  // Holds the offset from the beginning of the file at
  // which the first byte of the segment resides
  uint64_t p_offset = 0;
  // Holds the virtual address at which the first byte of the
  // segment resides in memory
  uint64_t p_vaddr = 0;
  // On systems for which physical addressing is relevant, this
  // member is reserved for the segment's physical address
  uint64_t p_paddr = 0;
  // Holds the number of bytes in the file image of
  // the segment.  It may be zero
  uint64_t p_filesz = 0;
  // Holds the number of bytes in the memory image
  // of the segment.  It may be zero
  uint64_t p_memsz = 0;
  uint64_t p_align = 0;
  // Holds the header's data.
  std::vector<char> data = {};
};

#define EI_NIDENT 16

#define EI_CLASS 4

struct Elf64_Ehdr {
  std::array<char, EI_NIDENT> e_ident;
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  Elf64_Addr e_entry;
  Elf64_Offset e_phoff;
  Elf64_Offset e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct Elf_Binary {
  Elf64_Ehdr elf_header;
  std::vector<Elf64_Phdr> loadable_phdrs;
};

#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3

/** A processed Executable and Linkable Format (ELF) file. */
class Elf {
 public:
  Elf(std::string path);

  ~Elf() {}

  /** Method to return the validity of the ELF parsing process. */
  bool isValid() const;

  /***/
  bool isDynamic() const;

  /***/
  std::shared_ptr<Elf_Binary> getExecutable() const;

  /***/
  std::shared_ptr<Elf_Binary> getInterpreter() const;

 private:
  /** Bool which holds if the ELF parsing was done correctly. */
  bool isValid_ = false;

  /***/
  std::string interpreterPath_;

  /***/
  bool isDynamic_ = 0;

  /***/
  std::shared_ptr<Elf_Binary> executable_ = nullptr;

  /***/
  std::shared_ptr<Elf_Binary> interpreter_ = nullptr;

  /***/
  Elf64_Ehdr parseElfEhdr(std::ifstream& elf_file);

  /***/
  std::vector<Elf64_Phdr> parseElfPhdrs(
      std::ifstream& elf_file, Elf64_Ehdr& Ehdr);

  /***/
  std::shared_ptr<Elf_Binary> parseElfBinary(std::string fpath);
};

}  // namespace simeng
