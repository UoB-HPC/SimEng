#pragma once

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

struct Elf64_Phdr {
  // Indicates what kind of segment this array element describes or
  // how to interpret the array element's information
  uint32_t p_type;
  // Holds the offset from the beginning of the file at
  // which the first byte of the segment resides
  uint64_t p_offset;
  // Holds the virtual address at which the first byte of the
  // segment resides in memory
  uint64_t p_vaddr;
  // On systems for which physical addressing is relevant, this
  // member is reserved for the segment's physical address
  uint64_t p_paddr;
  // Holds the number of bytes in the file image of
  // the segment.  It may be zero
  uint64_t p_filesz;
  // Holds the number of bytes in the memory image
  // of the segment.  It may be zero
  uint64_t p_memsz;
};

/** A processed Executable and Linkable Format (ELF) file. */
class Elf {
 public:
  Elf(std::string path, char** imagePointer);
  ~Elf();

  /** Returns the process image size */
  uint64_t getProcessImageSize() const;

  /** Returns if this ELF is valid */
  bool isValid() const;

  /** Returns the virtual address to which the system first transfers
   * control */
  uint64_t getEntryPoint() const;

  /** Returns the virtual address of the program header table */
  uint64_t getPhdrTableAddress() const;

  /** Returns the size of a program header entry */
  uint64_t getPhdrEntrySize() const;

  /** Returns the number of program headers */
  uint64_t getNumPhdr() const;

 private:
  /** The entry point of the program */
  uint64_t entryPoint_;

  /** A vector holding each of the program headers extracted from the ELF */
  std::vector<Elf64_Phdr> pheaders_;

  /** The program header entry size stored in the ELF header */
  uint16_t e_phentsize_;

  /** The number of entries in the program header table stored in the ELF header
   */
  uint16_t e_phnum_;

  /** Virtual address of the program header table */
  uint64_t phdrTableAddress_ = 0;

  /** Holds whether this ELF is valid for SimEng */
  bool isValid_ = false;

  /** The size of the process image */
  uint64_t processImageSize_;
};

}  // namespace simeng
