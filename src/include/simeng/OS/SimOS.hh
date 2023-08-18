#pragma once

#include <cstdint>
#include <functional>
#include <iostream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "simeng/Core.hh"
#include "simeng/OS/Constants.hh"
#include "simeng/OS/PageFrameAllocator.hh"
#include "simeng/OS/SyscallHandler.hh"
#include "simeng/OS/Vma.hh"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/arch/riscv/Instruction.hh"
#include "simeng/config/SimInfo.hh"
#include "simeng/memory/MMU.hh"
#include "simeng/memory/SimpleMem.hh"
#include "simeng/span.hh"

// Forward declare RegressionTest class so that it can be declared a friend.
class RegressionTest;

namespace simeng {
namespace OS {

using namespace simeng::OS::defaults;

// Program used when no executable is provided; counts down from
// 1024*1024, with an independent `orr` at the start of each branch.
static uint32_t hex_[8] = {
    0x320C03E0,  // orr w0, wzr, #1048576
    0x320003E1,  // orr w0, wzr, #1
    0x71000400,  // subs w0, w0, #1
    0x54FFFFC1,  // b.ne -8
                 // .exit:
    0xD2800000,  // mov x0, #0
    0xD2800BC8,  // mov x8, #94
    0xD4000001,  // svc #0
};

struct CoreInfo {
  uint16_t coreId;
  CoreStatus status;
  cpuContext ctx;
  uint64_t ticks;
};

struct CoreDesc {
  CoreInfo info;
  bool pendingResponseFromCore;
};

struct CoreProxy {
  std::function<void(uint16_t, bool)> getCoreInfo;
  std::function<void(uint16_t)> interrupt;
  std::function<void(uint16_t, cpuContext)> schedule;
};

struct CloneArgs {
  uint64_t flags;
  uint64_t stackPtr;
  uint64_t parentTidPtr;
  uint64_t tls;
  uint64_t childTidPtr;
  uint64_t parentTid;
  uint64_t coreID;
  Register retReg;
  uint64_t paddr;
};

/** A simple, lightweight Operating System kernel based on Linux to emulate
 * syscalls and manage process execution. */
class SimOS {
 public:
  /** Construct a SimOS object which creates the initial Process from a byte
   * stream. */
  SimOS(std::shared_ptr<simeng::memory::Mem> mem, simeng::span<char> instrBytes,
        std::function<void(const SyscallResult)> sendSyscallResultToCore);

  /** Construct a SimOS object from a binary file specified via the runtime
   * arguments of SimEng. */
  SimOS(std::shared_ptr<simeng::memory::Mem> mem, std::string executablePath,
        std::vector<std::string> executableArgs,
        std::function<void(const SyscallResult)> sendSyscallResultToCore);

  ~SimOS(){};

  /** Tick SimOS. */
  void tick();

  /** Create a new Process Object.
   * A span<char> is optionally passed into the function to indicate if the
   * Process is created via raw bytes or via a compiled binary.
   * Returns the tid of the process that was created. */
  uint64_t createProcess(span<char> instructionBytes = span<char>());

  /** Creates a new Process object that is a thread of the calling process.
   * `parentTid` is that of the parent (or calling process). */
  void cloneProcess(uint64_t flags, uint64_t stackPtr, uint64_t parentTidPtr,
                    uint64_t tls, uint64_t childTidPtr, uint64_t parentTid,
                    uint64_t coreID, Register retReg);

  void resumeClone(uint16_t coreId, CoreInfo cinfo);

  /** Get a process with specified `tid`. */
  const std::shared_ptr<Process>& getProcess(uint64_t tid);

  /** Get the number of active processes. */
  const size_t getNumProcesses() { return processes_.size(); }

  /** Terminate the process with threadID = `tid`, and set the corresponding
   * core to an idle state if applicable. */
  void terminateThread(uint64_t tid);

  /** Terminate all processes with threadGroupID = `tgid`, and set corresponding
   * cores to an idle state if applicable. */
  void terminateThreadGroup(uint64_t tgid);

  /** Method which allocates multiple page frames of size 'PAGE_SIZE' to cover
   * an address range of 'size' and returns the starting physical address. */
  uint64_t requestPageFrames(size_t size);

  /** Method which handles process specific page table translation. */
  uint64_t handleVAddrTranslation(uint64_t vaddr, uint64_t tid);

  /** This method returns a callback function that is passed to the MMU.
   * The callback function will be used by the MMU to handle TLB misses. The
   * callback invokes SimOS for virtual address translations. */
  VAddrTranslator getVAddrTranslator();

  /** Get shared_ptr to syscallHandler instance. */
  std::shared_ptr<SyscallHandler> getSyscallHandler() const {
    return syscallHandler_;
  }

  /** Register a core with the OS to enable process scheduling. */
  void registerCore(uint16_t coreId, CoreStatus status, cpuContext context,
                    bool readyToExecute);

  /** Check if OS has halted. */
  bool hasHalted() const { return halted_; };

  /** Unique pointer to host backed file mmap. */
  std::unique_ptr<HostBackedFileMMaps> const hfmmap_ =
      std::make_unique<HostBackedFileMMaps>();

  /** Retrieve the simulated nanoseconds elapsed since the core started. */
  uint64_t getSystemTimer() const;

  /** Receive the syscall from a core and pass onto the syscall handler. */
  void receiveSyscall(SyscallInfo syscallInfo) const;

  /** A getter for the receiveSyscall() function. */
  arch::sendSyscallToHandler getSyscallReceiver() {
    return [this](auto SyscallInfo) { receiveSyscall(SyscallInfo); };
  }

  /** This public method adds a process to the waitingProcs_ queue. */
  void addProcessToWaitQueue(std::shared_ptr<Process> procPtr) {
    waitingProcs_.push(procPtr);
  };

  void recieveCoreInfo(CoreInfo cinfo, uint16_t coreId, bool forClone);

  void recieveInterruptResponse(bool success, uint16_t coreId);

  void registerCoreProxy(CoreProxy proxy) { coreProxy_ = proxy; }

  void haltCore(cpuContext ctx, uint16_t coreId);

  /** Set up friend class with RegressionTest to enable exclusive access to
   * private functions. */
  friend class ::RegressionTest;

 private:
  /** Private constructor, called by all public constructors to perform common
   * logic. */
  SimOS(std::shared_ptr<simeng::memory::Mem> mem,
        std::function<void(const SyscallResult)> sendSyscallResultToCore);

  /** Construct the special file directory. */
  void createSpecialFileDirectory() const;

  /** The total number of times the SimOS class has been ticked. */
  uint64_t ticks_ = 0;

  /** The path of user defined Executable. */
  std::string executablePath_ = DEFAULT_STR;

  /** The runtime arguments of the user defined executable. */
  std::vector<std::string> executableArgs_ = {};

  /** The map of user-space processes running above the OS kernel.
   * Key = process' TID
   * Value = Shared pointer to process object with TID = key. */
  std::unordered_map<uint64_t, std::shared_ptr<Process>> processes_ = {};

  /** Queue of processes waiting to be scheduled. */
  std::queue<std::shared_ptr<Process>> waitingProcs_ = {};

  /** Queue of processes that have successfully sent an interrupt signal to a
   * core and are waiting to be scheduled on it. */
  std::queue<std::shared_ptr<Process>> scheduledProcs_ = {};

  std::vector<CoreDesc> coreDescs_ = {};

  /** Reference to the simulation memory shared pointer */
  std::shared_ptr<simeng::memory::Mem> memory_ = nullptr;

  /** SyscallHandler Object to process all syscalls. */
  std::shared_ptr<SyscallHandler> syscallHandler_;

  /** Port used for communication with the memory hierarchy. */
  std::shared_ptr<Port<std::unique_ptr<simeng::memory::MemPacket>>> memPort_ =
      nullptr;

  /** Port mediator used to connect the system classes to a memory hierarchy. */
  std::unique_ptr<
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>>
      connection_ = nullptr;

  /** Indicates if all processes have completed or a core has halted due to an
   * exception. */
  bool halted_ = false;

  /** The value of the next TID value that should be assigned to a process on
   * instantiation. */
  uint64_t nextFreeTID_ = 1;

  /** Reference to the PageFrameAllocator object.  */
  PageFrameAllocator pageFrameAllocator_;

  uint16_t pendingResponseFromCore_;

  CoreProxy coreProxy_;

  std::unordered_map<uint16_t, CloneArgs> cloneArgsMap_;
};

}  // namespace OS
}  // namespace simeng
