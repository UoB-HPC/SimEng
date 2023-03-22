#pragma once

#include <memory>

#include "simeng/Elf.hh"
#include "yaml-cpp/yaml.h"

namespace simeng {
namespace kernel {

namespace auxVec {
/** Labels for the entries in the auxiliary vector. */
enum labels {
  AT_NULL = 0,      /* end of vector */
  AT_IGNORE = 1,    /* entry should be ignored */
  AT_EXECFD = 2,    /* file descriptor of program */
  AT_PHDR = 3,      /* program headers for program */
  AT_PHENT = 4,     /* size of program header entry */
  AT_PHNUM = 5,     /* number of program headers */
  AT_PAGESZ = 6,    /* system page size */
  AT_BASE = 7,      /* base address of interpreter */
  AT_FLAGS = 8,     /* flags */
  AT_ENTRY = 9,     /* entry point of program */
  AT_NOTELF = 10,   /* program is not ELF */
  AT_UID = 11,      /* real uid */
  AT_EUID = 12,     /* effective uid */
  AT_GID = 13,      /* real gid */
  AT_EGID = 14,     /* effective gid */
  AT_PLATFORM = 15, /* string identifying CPU for optimizations */
  AT_HWCAP = 16,    /* arch dependent hints at CPU capabilities */
  AT_CLKTCK = 17    /* frequency at which times() increments */
};
}  // namespace auxVec

/** Align `address` to an `alignTo`-byte boundary by rounding up to the nearest
 * multiple. */
uint64_t alignToBoundary(uint64_t value, uint64_t boundary);

/** The initial state of a Linux process, constructed from a binary executable.
 *
 * The constructed process follows a typical layout:
 *
 * |---------------| <- start of stack
 * |     Stack     |    stack grows downwards
 * |-v-----------v-|
 * |               |
 * |-^-----------^-|
 * |  mmap region  |    mmap region grows upwards
 * |---------------| <- start of mmap region
 * |               |
 * |-^-----------^-|
 * |     Heap      |    heap grows upwards
 * |---------------| <- start of heap
 * |               |
 * |  ELF-defined  |
 * | process image |
 * |               |
 * |---------------| <- 0x0
 *
 */
class LinuxProcess {
 public:
  /** Construct a Linux process from a vector of command-line arguments.
   *
   * The first argument is a path to an executable ELF file. */
  LinuxProcess(const std::vector<std::string>& commandLine, YAML::Node config);

  /** Construct a Linux process from region of instruction memory, with the
   * entry point fixed at 0. */
  LinuxProcess(span<char> instructions, YAML::Node config);

  ~LinuxProcess();

  /** Get the address of the start of the heap region. */
  uint64_t getHeapStart() const;

  /** Get the address of the top of the stack. */
  uint64_t getStackStart() const;

  /** Get the address of the start of the mmap region. */
  uint64_t getMmapStart() const;

  /** Get the page size. */
  uint64_t getPageSize() const;

  /** Get a shared_ptr to process image. */
  std::shared_ptr<char> getProcessImage() const;

  /** Get the size of the process image. */
  uint64_t getProcessImageSize() const;

  /** Get the entry point. */
  uint64_t getEntryPoint() const;

  /** Get the initial stack pointer address. */
  uint64_t getStackPointer() const;

  /** Get the path of the executable. */
  std::string getPath() const;

  /** Check whether the process image was created successfully. */
  bool isValid() const;

 private:
  /** The size of the stack, in bytes. */
  const uint64_t STACK_SIZE;

  /** The space to reserve for the heap, in bytes. */
  const uint64_t HEAP_SIZE;

  /** Create and populate the initial process stack. */
  void createStack(char** processImage);

  /** The entry point of the process. */
  uint64_t entryPoint_ = 0;

  /** Program header table address */
  uint64_t progHeaderTableAddress_ = 0;

  /** Number of program headers */
  uint64_t numProgHeaders_ = 0;

  /** Size of program header entry */
  uint64_t progHeaderEntSize_ = 0;

  /** The address of the start of the heap region. */
  uint64_t heapStart_;

  /** The address of the start of region of memory given to mmap. */
  uint64_t mmapStart_;

  /** The page size of the process memory. */
  const uint64_t pageSize_ = 4096;

  /** The address of the stack pointer. */
  uint64_t stackPointer_;

  /** The process image size. */
  uint64_t size_;

  /** The process command and its arguments. */
  std::vector<std::string> commandLine_;

  /** Whether the process image was created successfully. */
  bool isValid_ = false;

  /** Shared pointer to processImage. */
  std::shared_ptr<char> processImage_;
};

}  // namespace kernel
}  // namespace simeng
