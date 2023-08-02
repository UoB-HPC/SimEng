#include "simeng/Elf.hh"

#include <fcntl.h>
#include <gelf.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>

#include "libelf.h"

namespace simeng {

std::map<uint64_t, std::string>* Elf::symbol_table_ =
    new std::map<uint64_t, std::string>();
/**
 * Extract information from an ELF binary.
 * 32-bit and 64-bit architectures have variance in the structs
 * used to define the structure of an ELF binary. All information
 * presented as documentation has been referenced from:
 * https://man7.org/linux/man-pages/man5/elf.5.html
 */

Elf::Elf(std::string path, char** imagePointer) {
  std::ifstream file(path, std::ios::binary);

  if (!file.is_open()) {
    return;
  }

  /**
   * In the Linux source tree the ELF header
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
    std::cerr << "[SimEng:Elf] Elf magic does not match" << std::endl;
    return;
  }

  /**
   * The fifth byte of the ELF Header identifies the architecture
   * of the ELF binary i.e 32-bit or 64-bit.
   */

  // Check whether this is a 32 or 64-bit executable
  char bitFormat;
  file.read(&bitFormat, sizeof(bitFormat));
  if (bitFormat != ElfBitFormat::Format64) {
    std::cerr << "[SimEng:Elf] Unsupported architecture detected in Elf"
              << std::endl;
    return;
  }

  isValid_ = true;

  /**
   * Starting from the 24th byte of the ELF header a 64-bit value
   * represents the virtual address to which the system first transfers
   * control, thus starting the process.
   * In `elf64_hdr` this value maps to the member `Elf64_Addr e_entry`.
   */

  // Seek to the entry point of the file.
  // The information in between is discarded
  file.seekg(0x18);
  file.read(reinterpret_cast<char*>(&entryPoint_), sizeof(entryPoint_));

  /**
   * Starting from the 32nd byte of the ELF Header a 64-bit value
   * represents the offset of the ELF Program header or
   * Program header table in the ELF file.
   * In `elf64_hdr` this value maps to the member `Elf64_Addr e_phoff`.
   */

  // Seek to the byte representing the start of the header offset table.
  // Holds the program header table's file offset in bytes.  If the file has no
  // program header table, this member holds zero
  uint64_t e_phoff = 0;
  file.read(reinterpret_cast<char*>(&e_phoff), sizeof(e_phoff));

  /**
   * Starting from the 54th byte of the ELF Header a 16-bit value indicates the
   * size in bytes of one entry in the file's program header table; all entries
   * are the same size. In the `elf64_hdr` struct this value maps to the member
   * `Elf64_Half e_phentsize`.
   */
  // Seek to the byte representing header entry size.
  file.seekg(0x36);
  file.read(reinterpret_cast<char*>(&e_phentsize_), sizeof(e_phentsize_));

  /** Starting from the 56th byte a 16-bit value represents the number
   * of program header entries in the ELF Program header table. In the
   * `elf64_hdr` struct this value maps to `Elf64_Half e_phnum`.
   */
  file.read(reinterpret_cast<char*>(&e_phnum_), sizeof(e_phnum_));

  // Resize the header to equal the number of header entries.
  pheaders_.resize(e_phnum_);
  processImageSize_ = 0;

  // Loop over all headers and extract them.
  for (size_t i = 0; i < e_phnum_; i++) {
    // Since all headers entries have the same size.
    // We can extract the nth header using the header offset
    // and header entry size.
    file.seekg(e_phoff + (i * e_phentsize_));
    auto& header = pheaders_[i];

    /**
     * Like the ELF Header, the ELF Program header is also defined
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
     * beginning of the file at which the first byte of the segment resides.
     */

    // Each address-related field is 8 bytes in a 64-bit ELF file
    const int fieldBytes = 8;
    file.read(reinterpret_cast<char*>(&(header.p_type)), sizeof(header.p_type));
    file.seekg(4, std::ios::cur);  // Skip flags
    file.read(reinterpret_cast<char*>(&(header.p_offset)), fieldBytes);
    file.read(reinterpret_cast<char*>(&(header.p_vaddr)), fieldBytes);
    file.read(reinterpret_cast<char*>(&(header.p_paddr)), fieldBytes);
    file.read(reinterpret_cast<char*>(&(header.p_filesz)), fieldBytes);
    file.read(reinterpret_cast<char*>(&(header.p_memsz)), fieldBytes);
    // Skip p_align

    // To construct the process we look for the largest virtual address and
    // add it to the memory size of the header. This way we obtain a very
    // large array which can hold data at large virtual address.
    // However, this way we end up creating a sparse array, in which most
    // of the entries are unused. Also, SimEng internally treats these
    // virtual address as physical addresses to index into this large array.
    if (header.p_vaddr + header.p_memsz > processImageSize_) {
      processImageSize_ = header.p_vaddr + header.p_memsz;
    }

    // Determine the virtual address of the header table in memory from
    // individual program headers. Used to populate the auxvec
    if (header.p_offset <= e_phoff &&
        e_phoff < header.p_offset + header.p_filesz) {
      phdrTableAddress_ = header.p_vaddr + (e_phoff - header.p_offset);
    }
  }

  *imagePointer = (char*)malloc(processImageSize_ * sizeof(char));
  /**
   * The ELF Program header has a member called `p_type`, which represents
   * the kind of data or memory segments described by the program header.
   * The value PT_LOAD=1 represents a loadable segment. In other words,
   * it contains initialized data that contributes to the program's
   * memory image.
   */

  // Process headers; only observe LOAD sections for this basic implementation
  for (const auto& header : pheaders_) {
    if (header.p_type == 1) {  // LOAD
      file.seekg(header.p_offset);
      // Read `p_filesz` bytes from `file` into the appropriate place in process
      // memory
      file.read(*imagePointer + header.p_vaddr, header.p_filesz);
    }
  }

  loadElfSymbols(path);

  file.close();
  return;
}

void Elf::loadElfSymbols(std::string path) {
  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    std::exit(1);
  }
  off_t off = lseek(fd, 0, SEEK_END);
  if (off < 0) {
    std::exit(1);
  }
  char* data_ = (char*)mmap(0, off, PROT_READ, MAP_SHARED, fd, 0);
  ::Elf* elf_m = elf_memory(data_, off);

  int sec_idx = 1;  // there is a 0 but it is nothing, go figure
  Elf_Scn* section = elf_getscn(elf_m, sec_idx);
  while (section) {
    Elf64_Shdr* shdr = elf64_getshdr(section);

    if (shdr->sh_type == SHT_SYMTAB) {
      Elf_Data* data = elf_getdata(section, nullptr);
      int count = shdr->sh_size / shdr->sh_entsize;

      // Loop through all the symbols.
      for (int i = 0; i < count; ++i) {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);
        char* sym_name = elf_strptr(elf_m, shdr->sh_link, sym.st_name);
        if (!sym_name || sym_name[0] == '$') continue;
        std::string symbol_name(sym_name);
        uint64_t address = sym.st_value;

        if (symbol_name == "exit") {
          std::cout << "<exit> symbol found at address: 0x" << std::hex
                    << address << std::dec << std::endl;
        }

        auto sym_table = get_symbol_table();
        sym_table->insert({address, symbol_name});
        // std::cout << sym_name << " addr " << std::hex << address <<
        // std::endl;
      }
    }
    ++sec_idx;
    section = elf_getscn(elf_m, sec_idx);
  }

  elf_end(elf_m);
  close(fd);
  munmap(data_, off);
}

Elf::~Elf() {}

uint64_t Elf::getProcessImageSize() const { return processImageSize_; }

uint64_t Elf::getEntryPoint() const { return entryPoint_; }

bool Elf::isValid() const { return isValid_; }

uint64_t Elf::getPhdrTableAddress() const { return phdrTableAddress_; }

uint64_t Elf::getPhdrEntrySize() const { return e_phentsize_; }

uint64_t Elf::getNumPhdr() const { return e_phnum_; }

}  // namespace simeng
