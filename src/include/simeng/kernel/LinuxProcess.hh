#pragma once

#include "simeng/Elf.hh"
#include "simeng/Translator.hh"

namespace simeng {
namespace kernel {

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
  /** Construct a Linux process from a vector of command-line arguments, a
   * possible coredump file, and a address translator.
   *
   * The first element of the command-line vector is a path to an executable ELF
   * file. */
  LinuxProcess(const std::vector<std::string>& commandLine,
               Translator& translator);

  /** Construct a Linux process from region of instruction memory, with the
   * entry point fixed at 0. */
  LinuxProcess(span<char> instructions, Translator& translator);

  ~LinuxProcess();

  /** Get the inital program break of the program. */
  uint64_t getProcessBrk() const;

  /** Get the inital program break of the simulation. */
  uint64_t getSimulationBrk() const;

  /** Get the address of the top of the stack. */
  uint64_t getStackStart() const;

  /** Get the initial address of the process mmap region. */
  uint64_t getProcessMmapStart() const;

  /** Get the initial address of the simulation mmap region. */
  uint64_t getSimulationMmapStart() const;

  /** Get the page size. */
  uint64_t getPageSize() const;

  /** Get the process image. */
  const span<char> getProcessImage() const;

  /** Get a section of the note segment of passed in from the ELF. */
  const NoteEntry getNote(uint32_t type) const;

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
  static const uint64_t STACK_SIZE = 1024 * 1024;  // 1MiB

  /** The space to reserve for the heap, in bytes. */
  static const uint64_t HEAP_SIZE = 1024 * 1024 * 10;  // 10MiB

  /** Create and populate the initial process stack. */
  void createStack();

  /** The entry point of the process. */
  uint64_t entryPoint_ = 0;

  /** The inital program break of the program. */
  uint64_t processBrk_ = 0;

  /** The inital program break of the simulation. */
  uint64_t simulationBrk_ = 0;

  /** The initial address for process memory given to mmap calls . */
  uint64_t processMmapStart_;

  /** The initial address for simulation memory given to mmap calls. */
  uint64_t simulationMmapStart_;

  /** The page size of the process memory. */
  const uint64_t pageSize_ = 4096;

  /** The address of the stack pointer. */
  uint64_t stackPointer_ = 0;

  /** The process image. */
  char* processImage_;

  /** The ELF NOTE segment. */
  std::vector<NoteEntry> noteSegment_;

  /** The process image size. */
  uint64_t size_;

  /** The process command and its arguments. */
  std::vector<std::string> commandLine_;

  /** The address translator between program virtual address space and SimEng
   * process memory. */
  Translator& translator_;

  /** Whether the process image was created successfully. */
  bool isValid_ = false;
};

}  // namespace kernel
}  // namespace simeng
