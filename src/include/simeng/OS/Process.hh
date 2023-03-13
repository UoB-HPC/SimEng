#pragma once

#include <sys/resource.h>

#include <functional>
#include <memory>

#include "simeng/Config.hh"
#include "simeng/Elf.hh"
#include "simeng/OS/FileDesc.hh"
#include "simeng/OS/MemRegion.hh"
#include "simeng/OS/PageTable.hh"
#include "simeng/SpecialFileDirGen.hh"

namespace simeng {

// Forward declaration of class simeng::memory::Mem;
namespace memory {
class Mem;
};

namespace OS {

using namespace simeng::OS::defaults;

/** Typedef for callback function used to send data to memory upon handling page
 * fault. */
typedef std::function<void(std::vector<char> data, uint64_t, size_t)>
    sendToMemory;

// Forward declaration for SimOS.
class SimOS;

enum procStatus { waiting, executing, completed, scheduled, sleeping };

/** Struct of a CPU context used for context switching. */
struct cpuContext {
  uint64_t TID;
  uint64_t pc;
  // SP only used in process construction. Actual value lives in regFile
  uint64_t sp;
  uint64_t progByteLen;
  std::vector<std::vector<RegisterValue>> regFile;
};

/** Align `value` to the `boundary`-byte by rounding up to the nearest
 * multiple. */
uint64_t alignToBoundary(uint64_t value, uint64_t boundary);

/** The initial state of a SimOS Process, constructed from a binary executable.
 *
 * The constructed process follows the layout described below and has the
 * following properties:
 *
 * a) Padding between each region is equal to the page size.
 * b) Each region's start address, end address and size are page aligned.
 * c) The stack grows downwards.
 * d) The heap grows upwards.
 * e) The mmap region grows upwards.
 * f) Region above the initial stack address contains all initial data for the
 * process to start i.e argv, env args, auxiliary variables.
 *
 * |---------------| <- stackStart (Start of the stack region)
 * |---------------| <- initStackPtr (Initial stack address available)
 * |     Stack     |
 * |               |
 * |-v-----------v-| <- stackEnd (End of the stack region)
 * |    Padding    |
 * |-^-----------^-| <- mmapEnd (End of mmap region)
 * |  Mmap region  |
 * |               |
 * |---------------| <- mmapstart (Start of mmap region)
 * |    Padding    |
 * |-^-----------^-| <- heapEnd (End of the heap region)
 * |     Heap      |
 * |               |
 * |---------------| <- heapStart (Start of stack region)
 * |    Padding    |
 * |---------------| <- End of the ELF-defined process image
 * |  ELF-defined  |
 * | process image |
 * |               |
 * |---------------| <- Lowest address in the process layout
 *
 */
class Process {
  /**  Make SimOS friend class of Process so it can access all private
   * variables. */
  friend class SimOS;

 public:
  /** Construct a SimOS Process from a vector of command-line arguments. The
   * first argument is a path to an executable ELF file. Size of the simulation
   * memory is also passed to check if the process image can fit inside the
   * simulation memory. */
  Process(const std::vector<std::string>& commandLine, SimOS* OS,
          std::vector<RegisterFileStructure> regFileStructure, uint64_t TGID,
          uint64_t TID, sendToMemory sendToMem, size_t simulationMemSize);

  /** Construct a SimOS Process from region of instruction memory, with the
   * entry point fixed at 0. Size of the simulation memory is also passed to
   * check if the process image can fit inside the simulation memory.*/
  Process(span<char> instructions, SimOS* OS,
          std::vector<RegisterFileStructure> regFileStructure, uint64_t TGID,
          uint64_t TID, sendToMemory sendToMem, size_t simulationMemSize);

  /** Default copy constructor for Process class. */
  Process(const Process& proc) = default;

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

  /** Updates the Process' TID. */
  void updateTID(const uint64_t tid) { TID_ = tid; }

  /** Method which handles a page fault. */
  uint64_t handlePageFault(uint64_t vaddr);

  /** Method which handles virtual address translation. */
  uint64_t translate(uint64_t vaddr) { return pageTable_->translate(vaddr); }

  /** Updates a Processes stack space; utilised after the `clone` syscall. */
  void updateStack(const uint64_t stackPtr) {
    memRegion_.updateStack(stackPtr);
  }

  /** Unique pointer to FileDescArray class.*/
  std::shared_ptr<FileDescArray> fdArray_;

  /** Current status of the process. */
  procStatus status_ = procStatus::waiting;

  /** The CPU context associated with this process. Used to enable context
   * switching between multiple processes. */
  cpuContext context_;

  /** The memory address at which the process should write its TID to.
   * Default value is 0.
   * It can be set using the `clone` syscall if the CLONE_CHILD_SETTID flag is
   * present.
   * If updated, the very first thing the new thread does is to write
   * its TID at this address. */
  uint64_t setChildTid_ = 0;

  /** The memory address of where a thread should write 0 to on termination if
   * it shares memory with other processes.
   * Default value is 0.
   * It can be set using the `clone` syscall if the CLONE_CHILD_CLEARTID flag is
   * present, or by calling the `set_tid_address` syscall. */
  uint64_t clearChildTid_ = 0;

  /** The rlimit struct for RLIMIT_STACK. RLIM_INF used to represent
   * RLIM_INFINITY in Linux. */
  rlimit stackRlim = {syscalls::prlimit::RLIM_INF, syscalls::prlimit::RLIM_INF};

 private:
  /** Create and populate the initial process stack and returns the stack
   * pointer. */
  uint64_t createStack(uint64_t stackStart);

  /** Initialises the Process' context_ arguments to the appropriate values. */
  void initContext(const uint64_t stackPtr,
                   const std::vector<RegisterFileStructure>& regFileStructure);

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
   * A thread group's leader's TID will be equal to the TGID. */
  uint64_t TID_;

  /** Reference to a page table */
  std::shared_ptr<PageTable> pageTable_ = nullptr;

  /** Reference to the SimOS object. */
  SimOS* OS_;

  /** Callback function used to write data to the simulation memory without
   * incurring any latency. This callback is used to write process
   * initialisation data during process creation to the simulation memory. It is
   * also used to write file data (if present) to the simulation memory after
   * handling a page fault */
  sendToMemory sendToMem_;
};

}  // namespace OS
}  // namespace simeng
