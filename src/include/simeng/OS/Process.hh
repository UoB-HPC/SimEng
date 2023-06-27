#pragma once

#include <sys/resource.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

#include "simeng/Config.hh"
#include "simeng/Elf.hh"
#include "simeng/OS/FileDesc.hh"
#include "simeng/OS/MemRegion.hh"
#include "simeng/OS/PageTable.hh"
#include "simeng/RegisterFileSet.hh"
#include "simeng/SpecialFileDirGen.hh"

namespace simeng {

// Forward declaration of class simeng::memory::Mem;
namespace memory {
class Mem;
};

namespace OS {

namespace auxVec {
// Labels for the entries in the auxiliary vector
enum labels {
  AT_NULL = 0,       // End of vector
  AT_IGNORE = 1,     // Entry should be ignored
  AT_EXECFD = 2,     // File descriptor of program
  AT_PHDR = 3,       // Program headers for program
  AT_PHENT = 4,      // Size of program header entry
  AT_PHNUM = 5,      // Number of program headers
  AT_PAGESZ = 6,     // System page size
  AT_BASE = 7,       // Base address of interpreter
  AT_FLAGS = 8,      // Flags
  AT_ENTRY = 9,      // Entry point of program
  AT_NOTELF = 10,    // Program is not ELF
  AT_UID = 11,       // Real uid
  AT_EUID = 12,      // Effective uid
  AT_GID = 13,       // Real gid
  AT_EGID = 14,      // Effective gid
  AT_PLATFORM = 15,  // String identifying CPU for optimizations
  AT_HWCAP = 16,     // Arch dependent hints at CPU capabilities
  AT_CLKTCK = 17     // Frequency at which times() increments
};
}  // namespace auxVec

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
  Process(SimOS* OS, uint64_t TGID, uint64_t TID, sendToMemory sendToMem);

  /** Default copy constructor for Process class. */
  Process(const Process& proc) = default;

  ~Process();

  /** Construct a SimOS Process from a vector of command-line arguments. The
   * first argument is a path to an executable ELF file. Size of the simulation
   * memory is also passed to check if the process image can fit inside the
   * simulation memory. */
  template <class T>
  void init(const std::vector<std::string>& commandLine,
            std::vector<RegisterFileStructure> regFileStructure,
            size_t simMemSize) {
    commandLine_ = commandLine;
    // Parse the Elf file.
    assert(commandLine.size() > 0);
    Elf elf(commandLine[0]);

    std::function<uint64_t(uint64_t, size_t)> unmapFn =
        [this](uint64_t vaddr, size_t size) -> uint64_t {
      uint64_t value = pageTable_->deleteMapping(vaddr, size);
      if (value ==
          (masks::faults::pagetable::FAULT | masks::faults::pagetable::UNMAP)) {
        std::cerr << "[SimEng:Process] Mapping doesn't exist for vaddr: "
                  << vaddr << " and length: " << size << std::endl;
      }
      return value;
    };

    memRegion_ = MemRegion(unmapFn);
    setupMemRegion<T>();
    uint64_t stack_top = memRegion_.stackRegion_.end;

    loadElf(elf);
    uint64_t stackPtr = createStack(stack_top);
    updateStack(stackPtr);

    // Initialise context
    initContext(stackPtr, regFileStructure);

    // Setup architecture stuff
    archSetup<T>();
    isValid_ = true;
  }

  /** Construct a SimOS Process from region of instruction memory, with the
   * entry point fixed at 0. Size of the simulation memory is also passed to
   * check if the process image can fit inside the simulation memory.*/
  template <class T>
  void init(span<char> instructions,
            std::vector<RegisterFileStructure> regFileStructure,
            size_t simMemSize) {
    // Parse the Elf file.
    commandLine_.push_back("\0");

    loadInstructions(instructions, simMemSize);
    uint64_t stack_top = memRegion_.stackRegion_.end;
    uint64_t stackPtr = createStack(stack_top);
    memRegion_.updateStack(stackPtr);

    initContext(stackPtr, regFileStructure);
    archSetup<T>();
    isValid_ = true;
  }

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

  /** Updates a Processes stack space. */
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
  rlimit stackRlim_ = {syscalls::prlimit::RLIM_INF,
                       syscalls::prlimit::RLIM_INF};

 private:
  /** Create and populate the initial process stack and returns the stack
   * pointer. */
  uint64_t createStack(uint64_t stackStart);

  /** Initialises the Process' context_ arguments to the appropriate values. */
  void initContext(const uint64_t stackPtr,
                   const std::vector<RegisterFileStructure>& regFileStructure);

  /***/
  template <class T>
  void setupMemRegion();

  /***/
  void loadInterpreter(Elf& elf);

  /***/
  void loadElf(Elf& elf);

  /***/
  void loadInstructions(span<char>& instructions, size_t simMemSize);

  /***/
  template <class T>
  void archSetup();

  /** MemRegion of the Process Image. */
  MemRegion memRegion_;

  /***/
  bool isDynamic_ = false;

  /** The entry point of the process. */
  uint64_t elfEntryPoint_ = 0;

  /***/
  uint64_t interpEntryPoint_ = 0;

  /** Program header table virtual address */
  uint64_t progHeaderTableAddress_ = 0;

  /** Number of program headers */
  uint64_t numProgHeaders_ = 0;

  /** Size of program header entry */
  uint64_t progHeaderEntSize_ = 0;

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
