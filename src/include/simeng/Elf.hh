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
  char* headerData = nullptr;
};

/** A processed Executable and Linkable Format (ELF) file. */
class Elf {
 public:
  Elf(std::string path);
  ~Elf();

  /** Method to return ELF process image size. */
  uint64_t getProcessImageSize() const;

  /** Method to return validility of the ELF parsing process. */
  bool isValid() const;

  /** Method which returns the entry point. */
  uint64_t getEntryPoint() const;

  /** Method which returns all processed ELF Headers. */
  std::vector<ElfHeader*>& getProcessedHeaders();

  /** Method which return maximum virtual address from the processed headers. */
  uint64_t getMaxVirtAddr();

 private:
  /** Entry point of the ELF. */
  uint64_t entryPoint_;
  /** Vector which holds all ELF headers. */
  std::vector<ElfHeader*> headers_;
  /** Bool which holds if the ELF parsing was done correctly. */
  bool isValid_ = false;
  /** Size of the ELF image. */
  uint64_t processImageSize_ = 0;
  /** Vector which holds all processed ELF headers. */
  std::vector<ElfHeader*> processedHeaders_;
  /** Max virtual address from ELF headers. */
  uint64_t maxVirtAddr_ = 0;
};

}  // namespace simeng
