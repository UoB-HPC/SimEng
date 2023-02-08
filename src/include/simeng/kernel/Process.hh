#pragma once

#include <memory>

#include "simeng/Config.hh"
#include "simeng/Elf.hh"
#include "simeng/kernel/MemRegion.hh"

namespace simeng {

// Forward declaration of class simeng::memory::Mem;
namespace memory {
class Mem;
};

namespace kernel {

// TODO : Move to more appropriate class (SimOS).
/** The page size of the process memory. */
static constexpr uint64_t pageSize_ = 4096;

enum procStatus { waiting, executing, completed, scheduled };

/** Struct of a CPU context used for context switching. */
struct cpuContext {
  uint64_t TID;
  uint64_t pc;
  // SP only used in process construction. Actual value lives in regFile
  uint64_t sp;
  uint64_t progByteLen;
  std::vector<std::vector<RegisterValue>> regFile;
};

/** Align `address` to an `alignTo`-byte boundary by rounding up to the nearest
 * multiple. */
uint64_t alignToBoundary(uint64_t value, uint64_t boundary);

/** The initial state of a SimOS Process, constructed from a binary executable.
 *
 * The constructed process follows a typical layout in memory:
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
class Process {
 public:
  /** Construct a SimOS Process from a vector of command-line arguments.
   *
   * The first argument is a path to an executable ELF file. */
  Process(const std::vector<std::string>& commandLine,
          std::shared_ptr<simeng::memory::Mem> memory,
          std::vector<RegisterFileStructure> regFileStructure, uint64_t TGID,
          uint64_t TID);

  /** Construct a SimOS Process from region of instruction memory, with the
   * entry point fixed at 0. */
  Process(span<char> instructions, std::shared_ptr<simeng::memory::Mem> memory,
          std::vector<RegisterFileStructure> regFileStructure, uint64_t TGID,
          uint64_t TID);

  ~Process();

  /** Get the address of the start of the heap region. */
  uint64_t getHeapStart() const;

  /** Get the address of the top of the stack. */
  uint64_t getStackStart() const;

  /** Get the address of the start of the mmap region. */
  uint64_t getMmapStart() const;

  /** Get the page size. */
  uint64_t getPageSize() const;

  /** Get the size of the process image. */
  uint64_t getProcessImageSize() const;

  /** Get the entry point. */
  uint64_t getEntryPoint() const;

  /** Get the initial stack pointer address. */
  uint64_t getStackPointer() const;

  /** Get the path of the executable. */
  std::string getPath() const;

  /** Get the memory region for this process. */
  MemRegion& getMemRegion() { return memRegion_; }

  /** Check whether the process image was created successfully. */
  bool isValid() const;

  /** Get the process' TGID. */
  uint64_t getTGID() const { return TGID_; }

  /** Get the process' TID. */
  uint64_t getTID() const { return TID_; }

  /** The virtual file descriptor mapping table. */
  std::vector<int64_t> fileDescriptorTable_;

  /** Set of deallocated virtual file descriptors available for reuse. */
  std::set<int64_t> freeFileDescriptors_;

  // Thread state
  // TODO: Support multiple threads per process
  /** The clear_child_tid value. */
  uint64_t clearChildTid = 0;

  /** Current status of the process. */
  procStatus status_ = procStatus::waiting;

  /** The CPU context associated with this process. Used to enable context
   * switching between multiple processes. */
  cpuContext context_;

 private:
  /** Create and populate the initial process stack and returns the stack
   * pointer. */
  uint64_t createStack(char** processImage, uint64_t stackStart);

  /** MemRegion of the Process Image. */
  MemRegion memRegion_;

  /** The entry point of the process. */
  uint64_t entryPoint_ = 0;

  /** The process command and its arguments. */
  std::vector<std::string> commandLine_;

  /** Whether the process image was created successfully. */
  bool isValid_ = false;

  /** The process' Thread Group ID, exactly equivalent to its Process ID (PID).
   */
  uint64_t TGID_;

  /** The process' Thread ID - a globally unique identifier.
   * A thread group's leader TID will be equal to the TGID. */
  uint64_t TID_;
};

}  // namespace kernel
}  // namespace simeng
