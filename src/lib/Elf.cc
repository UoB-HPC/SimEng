#include "simeng/Elf.hh"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>

#include "simeng/util/Math.hh"
#include "simeng/version.hh"

namespace simeng {

/** Extract information from an ELF binary.
 * 32-bit and 64-bit architectures have variance in the structs
 * used to define the structure of an ELF binary. All information
 * presented as documentation has been referenced from:
 * https://man7.org/linux/man-pages/man5/elf.5.html */

Elf64_Ehdr Elf::parseElfEhdr(std::ifstream& elf_file) {
  Elf64_Ehdr ehdr;
  /** In the Linux source tree the ELF header
   * is defined by the elf64_hdr struct for 64-bit systems.
   * `elf64_hdr->e_ident` is an array of 16 bytes which specifies
   * how to interpret the ELF file, independent of the
   * processor or the file's remaining contents. All ELF
   * files start with the ELF header. */
  elf_file.seekg(0);

  std::array<char, EI_NIDENT> eident;
  elf_file.read(eident.data(), EI_NIDENT);
  ehdr.e_ident = eident;

  elf_file.read(reinterpret_cast<char*>(&ehdr.e_type), sizeof(ehdr.e_type));
  elf_file.read(
      reinterpret_cast<char*>(&ehdr.e_machine), sizeof(ehdr.e_machine));
  elf_file.read(
      reinterpret_cast<char*>(&ehdr.e_version), sizeof(ehdr.e_version));
  /** Starting from the 24th byte of the ELF header a 64-bit value
   * represents the virtual address to which the system first transfers
   * control, thus starting the process.
   * In `elf64_hdr` this value maps to the member `Elf64_Addr e_entry`. */

  // Seek to the entry point of the file.
  // The information in between is discarded
  elf_file.read(reinterpret_cast<char*>(&ehdr.e_entry), sizeof(ehdr.e_entry));
  /** Starting from the 32nd byte of the ELF Header a 64-bit value
   * represents the offset of the ELF Program header or
   * Program header table in the ELF file.
   * In `elf64_hdr` this value maps to the member `Elf64_Addr e_phoff`. */

  // Seek to the byte representing the start of the header offset table.
  // Holds the program header table's file offset in bytes.  If the file has no
  // program header table, this member holds zero
  elf_file.read(reinterpret_cast<char*>(&ehdr.e_phoff), sizeof(ehdr.e_phoff));
  elf_file.read(reinterpret_cast<char*>(&ehdr.e_shoff), sizeof(ehdr.e_shoff));
  elf_file.read(reinterpret_cast<char*>(&ehdr.e_flags), sizeof(ehdr.e_flags));
  elf_file.read(reinterpret_cast<char*>(&ehdr.e_ehsize), sizeof(ehdr.e_ehsize));
  /** Starting 54th byte of the ELF Header a 16-bit value indicates
   * the size of each entry in the ELF Program header. In the `elf64_hdr`
   * struct this value maps to the member `Elf64_Half e_phentsize`. All
   * header entries have the same size.
   * Starting from the 56th byte a 16-bit value represents the number
   * of header entries in the ELF Program header. In the `elf64_hdr`
   * struct this value maps to `Elf64_Half e_phnum`. */

  // Seek to the byte representing header entry size.
  elf_file.read(
      reinterpret_cast<char*>(&ehdr.e_phentsize), sizeof(ehdr.e_phentsize));
  /** Starting from the 56th byte a 16-bit value represents the number
   * of program header entries in the ELF Program header table. In the
   * `elf64_hdr` struct this value maps to `Elf64_Half e_phnum`.
   */
  elf_file.read(reinterpret_cast<char*>(&ehdr.e_phnum), sizeof(ehdr.e_phnum));
  elf_file.read(
      reinterpret_cast<char*>(&ehdr.e_shentsize), sizeof(ehdr.e_shentsize));
  elf_file.read(reinterpret_cast<char*>(&ehdr.e_shnum), sizeof(ehdr.e_shnum));
  elf_file.read(
      reinterpret_cast<char*>(&ehdr.e_shstrndx), sizeof(ehdr.e_shstrndx));
  return ehdr;
}

std::vector<Elf64_Phdr> Elf::parseElfPhdrs(
    std::ifstream& elf_file, Elf64_Ehdr& ehdr) {
  std::vector<Elf64_Phdr> hdrs;
  for (uint16_t x = 0; x < ehdr.e_phnum; x++) {
    /** Like the ELF Header, the ELF Program header is also defined
     * using a struct:
     * typedef struct {
     *    uint32_t   p_type;
     *    uint32_t   p_flags;
     *    Elf64_Off  p_offset;
     *    Elf64_Addr p_vaddr;
     *    Elf64_Addr p_paddr;
     *    uint64_t   p_filesz;
     *    uint64_t   p_memsz;
     *    uint64_t   p_align;
     *  } Elf64_Phdr;
     *
     * The ELF Program header table is an array of structures,
     * each describing a segment or other information the system
     * needs to prepare the program for execution. A segment
     * contains one or more sections (ELF Program Section).
     *
     * The `p_vaddr` field holds the virtual address at which the first
     * byte of the segment resides in memory and the `p_memsz` field
     * holds the number of bytes in the memory image of the segment.
     * It may be zero. The `p_offset` member holds the offset from the
     * beginning of the file at which the first byte of the segment resides. */

    // Each address-related field is 8 bytes in a 64-bit ELF file
    uint32_t offset = ehdr.e_phoff + (x * ehdr.e_phentsize);
    uint8_t fieldBytes = 8;
    Elf64_Phdr phdr;
    // Since all headers entries have the same size.
    // We can extract the nth header using the header offset
    // and header entry size.
    elf_file.seekg(offset);
    elf_file.read(reinterpret_cast<char*>(&(phdr.p_type)), sizeof(phdr.p_type));
    elf_file.read(
        reinterpret_cast<char*>(&(phdr.p_flags)), sizeof(phdr.p_flags));
    elf_file.read(reinterpret_cast<char*>(&(phdr.p_offset)), fieldBytes);
    elf_file.read(reinterpret_cast<char*>(&(phdr.p_vaddr)), fieldBytes);
    elf_file.read(reinterpret_cast<char*>(&(phdr.p_paddr)), fieldBytes);
    elf_file.read(reinterpret_cast<char*>(&(phdr.p_filesz)), fieldBytes);
    elf_file.read(reinterpret_cast<char*>(&(phdr.p_memsz)), fieldBytes);
    elf_file.read(reinterpret_cast<char*>(&(phdr.p_align)), fieldBytes);
    /** The ELF Program header has a member called `p_type`, which represents
     * the kind of data or memory segments described by the program header.
     * The value PT_LOAD=1 represents a loadable segment. In other words,
     * it contains initialized data that contributes to the program's
     * memory image. */

    if (phdr.p_type == 1 || phdr.p_type == 3) {
      phdr.data.resize(phdr.p_filesz);
      elf_file.seekg(phdr.p_offset);
      elf_file.read(phdr.data.data(), phdr.p_filesz);
    }
    if (phdr.p_type == 1) hdrs.push_back(phdr);
    if (phdr.p_type == 3) isDynamic_ = true;
  }
  return hdrs;
}

std::shared_ptr<Elf_Binary> Elf::parseElfBinary(std::string fpath) {
  std::ifstream file(fpath, std::ios::binary);
  if (!file.is_open()) {
    // TODO: Error message
    std::exit(1);
  }
  char elfMagic[4] = {0x7f, 'E', 'L', 'F'};
  auto ehdr = parseElfEhdr(file);
  if (std::memcmp(elfMagic, ehdr.e_ident.data(), sizeof(elfMagic))) {
    std::cerr << "[SimEng:Elf] Elf magic does not match" << std::endl;
    std::exit(1);
  }
  if (ehdr.e_ident[EI_CLASS] != ElfBitFormat::Format64) {
    std::cerr << "[SimEng:Elf] Unsupported architecture detected in Elf"
              << std::endl;
    std::exit(1);
  }

  auto phdrs = parseElfPhdrs(file, ehdr);
  file.close();
  return std::shared_ptr<Elf_Binary>(new Elf_Binary{ehdr, phdrs});
}

Elf::Elf(std::string path) {
  executable_ = parseElfBinary(path);
  if (isDynamic_) {
    // Override path of binary supplied interpreter by one specified by user.
    // Because host interpreter can be different from interpreter the binary
    // specifies
    interpreterPath_ =
        "/home/rahat/local/aarch64-linux-gnu-8/aarch64-linux-gnu/libc/lib/"
        "ld-linux-aarch64.so.1";
    interpreter_ = parseElfBinary(interpreterPath_);
  }
}

bool Elf::isValid() const { return isValid_; }

bool Elf::isDynamic() const { return isDynamic_; }

std::shared_ptr<Elf_Binary> Elf::getExecutable() const { return executable_; }

std::shared_ptr<Elf_Binary> Elf::getInterpreter() const { return interpreter_; }

}  // namespace simeng
