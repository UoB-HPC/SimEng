#include "simeng/OS/SimOS.hh"

#include "simeng/OS/Constants.hh"
#include "simeng/OS/Process.hh"

/** The size of each time slice a process has. */
static constexpr uint64_t execTicks = 30000;

namespace simeng {
namespace OS {

SimOS::SimOS(std::shared_ptr<simeng::memory::Mem> mem,
             simeng::span<char> instrBytes)
    : SimOS(mem) {
  // Create the initial Process
  createProcess(instrBytes);
}

SimOS::SimOS(std::shared_ptr<simeng::memory::Mem> mem,
             std::string executablePath,
             std::vector<std::string> executableArgs)
    : SimOS(mem) {
  executablePath_ = executablePath;
  executableArgs_ = executableArgs;
  // Create the initial Process
  createProcess();
}

// The Private constructor
SimOS::SimOS(std::shared_ptr<simeng::memory::Mem> mem)
    : memory_(mem),
      pageFrameAllocator_(PageFrameAllocator(mem->getMemorySize())) {
  // Create tge syscall handler
  syscallHandler_ = std::make_shared<SyscallHandler>(this, mem);

  // Create the Special Files directory if indicated to do so in Config file
  if (Config::get()["CPU-Info"]["Generate-Special-Dir"].as<bool>() == true)
    createSpecialFileDirectory();
}

void SimOS::tick() {
  ticks_++;

  // Check if simulation halted
  if (halted_) {
    return;
  }

  syscallHandler_->tick();

  // Check for empty processes_ unordered_map
  if (processes_.size() == 0) {
    halted_ = true;
    return;
  }

  /** Scheduling behaviour :
   * 1. All processes start in a waiting state, and are placed in the
   * 'waitingProc' queue.
   *
   * 2. All cores are looped over, checking their status. If there is a process
   * at the front of the waitingProc queue then a currently executing core will
   * be tested to see if it should perform a context switch to the waiting
   * process. If the core has been executing for longer than execTicks then an
   * interupt signal is sent to test if a context switch can be made.
   *
   * 3. If the interrupt signal is successful, then the head of waitingProcs
   * queue is put into scheduled queue.
   *
   * 4. In order to schedule a process onto a core, a core must be in an Idle
   * state. An Idle core can only be scheduled a process from the scheduledProcs
   * queue, i.e. a process which has previously triggered a successful interupt
   * signal.
   *
   * 5. When a process is successfully scheduled, it is removed from the
   * scheduledProcs queue.
   *
   * 6. When a process is de-scheduled from a core it goes back into a waiting
   * state and is pushed to the back of the waitingProcs queue.
   *
   * By using two queues, we ensure that a single process will not interupt
   * multiple cores. This is due to :
   *    a. Only a process in the waitingProc queue can cause an interupt
   *    b. On a successful interupt, the process that caused it is moved to the
   * scheduledProc queue
   *    c. Only processes in the scheduledProc queue can be scheduled onto a
   * core, unless the scheduledProc queue is empty and a core is idle. In this
   * case a process from waitingProcs_ can jump ahead and be scheduled onto the
   * waiting core
   *
   * If not for this process, then a waitingProc could tell more executing cores
   * to context switch given a core is likely to be in a switching state (post
   * successful interupt, pre Idle state) for multiple cycles.
   * */

  // Loop over all cores, apply correct behaviour based on state
  for (auto core : cores_) {
    switch (core->getStatus()) {
      case CoreStatus::halted: {
        // Core has had fatal fault. Change SimOS status and return
        halted_ = true;
        return;
      }
      case CoreStatus::idle: {
        // Core is idle, schedule head of scheduledProc queue
        // Remove all completed processes from scheduledProcs_ queue
        while (!scheduledProcs_.empty() &&
               (scheduledProcs_.front()->status_ == procStatus::completed)) {
          scheduledProcs_.pop();
        }
        // Get context of process that was executing on core before interrupt
        // was signalled
        OS::cpuContext currContext = core->getCurrentContext();
        // Core's stored TID will equal -1 if no process has been previously
        // scheduled (i.e. on first tick of simulation)
        if (currContext.TID != -1) {
          // Find the corresponding process in map
          auto procItr = processes_.find(currContext.TID);
          // If proccess can't be found then it has been terminated so no need
          // to update context.
          if (procItr != processes_.end()) {
            auto currProc = procItr->second;
            assert((currProc->status_ == procStatus::executing) &&
                   "[SimEng:SimOS] Process updated when not in executing "
                   "state.");
            // Only update values which have changed
            currProc->context_.pc = currContext.pc;
            currProc->context_.regFile = currContext.regFile;
            // Change status from Executing to Waiting
            if (currProc->status_ != procStatus::sleeping) {
              currProc->status_ = procStatus::waiting;
              waitingProcs_.push(currProc);
            }
          }
        }
        if (!scheduledProcs_.empty()) {
          // Schedule new process on core
          core->schedule(scheduledProcs_.front()->context_);
          // Update newly scheduled process' status
          scheduledProcs_.front()->status_ = procStatus::executing;
          // Remove process from waiting queue
          scheduledProcs_.pop();
        } else if (!waitingProcs_.empty()) {
          // If nothing inside scheduledProcs_, check if there are any processes
          // inside waitingProcs which can jump ahead
          core->schedule(waitingProcs_.front()->context_);
          // Update newly scheduled process' status
          waitingProcs_.front()->status_ = procStatus::executing;
          // Remove process from waiting queue
          waitingProcs_.pop();
        }
        break;
      }
      case CoreStatus::executing: {
        // Core is executing, test if interrupt should be made
        // Remove all completed processes from waitingProcs_ queue
        while (!waitingProcs_.empty() &&
               (waitingProcs_.front()->status_ == procStatus::completed)) {
          waitingProcs_.pop();
        }
        bool canSched = !waitingProcs_.empty();
        canSched = canSched && (core->getCurrentProcTicks() > execTicks);
        canSched = canSched && core->interrupt();
        if (canSched) {
          // Interrupt signalled successfully, move waitingProc to sheduledProcs
          // queue
          waitingProcs_.front()->status_ = procStatus::scheduled;
          scheduledProcs_.push(waitingProcs_.front());
          waitingProcs_.pop();
        }
        break;
      }
      case CoreStatus::switching: {
        // Core is currently preparing to switch process, do nothing this cycle
        break;
      }
    }
  }
}

uint64_t SimOS::createProcess(span<char> instructionBytes) {
  // Callback function used to write data to the simulation memory without
  // incurring any latency. This function will be used to write data to the
  // simulation memory during process creation and while handling page faults.
  auto sendToMem = [this](std::vector<char> data, uint64_t addr, size_t size) {
    memory_->sendUntimedData(data, addr, size);
  };

  // Temporarily create the architecture, with knowledge of the OS
  std::unique_ptr<simeng::arch::Architecture> arch;
  if (Config::get()["Core"]["ISA"].as<std::string>() == "rv64") {
    arch = std::make_unique<simeng::arch::riscv::Architecture>();
  } else if (Config::get()["Core"]["ISA"].as<std::string>() == "AArch64") {
    arch = std::make_unique<simeng::arch::aarch64::Architecture>();
  }

  // Get structure of Architectural register file
  std::vector<RegisterFileStructure> regFileStructure =
      arch->getRegisterFileStructures();

  // Get the tid for new Process
  uint64_t tid = nextFreeTID_;
  nextFreeTID_++;

  if (!instructionBytes.empty()) {
    // Construct Process from `instructionBytes`. As this is a new process, the
    // TID = TGID.
    processes_.emplace(tid, std::make_shared<Process>(
                                instructionBytes, this, regFileStructure, tid,
                                tid, sendToMem, memory_->getMemorySize()));
    // Raise error if created process is not valid
    if (!processes_[tid]->isValid()) {
      std::cerr << "[SimEng:SimOS] Could not create process based on "
                   "supplied instruction span"
                << std::endl;
      exit(1);
    }
  } else {
    // Construct Process from specified binary file
    assert(executablePath_ != DEFAULT_STR &&
           "[SimEng:SimOS] Tried to construct a Process without specifying a "
           "pre-compiled binary or raw assembly byte stream.");
    // Concatenate the command line arguments into a single vector and
    // create the process image
    std::vector<std::string> commandLine = {executablePath_};
    commandLine.insert(commandLine.end(), executableArgs_.begin(),
                       executableArgs_.end());

    // Create new Process. As this is a new process, the TID = TGID.
    processes_.emplace(tid, std::make_shared<Process>(
                                commandLine, this, regFileStructure, tid, tid,
                                sendToMem, memory_->getMemorySize()));

    // Raise error if created process is not valid
    if (!processes_[tid]->isValid()) {
      std::cerr << "[SimEng:SimOS] Could not read/parse " << commandLine[0]
                << std::endl;
      exit(1);
    }
  }

  // Set Initial state of registers
  if (Config::get()["Core"]["ISA"].as<std::string>() == "rv64") {
    // Set the stack pointer register
    processes_[tid]->context_.regFile[arch::riscv::RegisterType::GENERAL][2] = {
        processes_[tid]->context_.sp, 8};
  } else if (Config::get()["Core"]["ISA"].as<std::string>() == "AArch64") {
    // Set the stack pointer register
    processes_[tid]->context_.regFile[arch::aarch64::RegisterType::GENERAL]
                                     [31] = {processes_[tid]->context_.sp, 8};
    // Set the system registers
    // Temporary: state that DCZ can support clearing 64 bytes at a time,
    // but is disabled due to bit 4 being set
    processes_[tid]->context_.regFile[arch::aarch64::RegisterType::SYSTEM]
                                     [arch->getSystemRegisterTag(
                                         ARM64_SYSREG_DCZID_EL0)] = {
        static_cast<uint64_t>(0b10100), 8};
  }

  processes_[tid]->status_ = procStatus::waiting;
  waitingProcs_.push(processes_[tid]);

  return tid;
}

const std::shared_ptr<Process>& SimOS::getProcess(uint64_t tid) {
  auto proc = processes_.find(tid);
  if (proc == processes_.end()) {
    // If TID doesn't exist then hard exit
    std::cerr << "[SimEng:SimOS] ERROR : Process with TID `" << tid
              << "` does not exist.\n";
    exit(1);
  }
  return proc->second;
}

void SimOS::terminateThread(uint64_t tid) {
  auto proc = processes_.find(tid);
  if (proc == processes_.end()) {
    // If process with TID doesn't exist, return early
    return;
  }
  // If clear_chilt_tid is non-zero then write 0 to this address
  uint64_t addr = proc->second->clearChildTid_;
  if (addr) {
    memory_->sendUntimedData({0}, addr, 1);
    // TODO: When `futex` has been implemented, perform
    // futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
  }
  // Set status to complete so it can be removed from the relevant queue in
  // tick()
  proc->second->status_ = procStatus::completed;
  // Remove the FutexInfo struct associated with the process.
  syscallHandler_->removeFutexInfo(proc->second->getTGID(), tid);
  // Remove from processes_
  processes_.erase(tid);
}

void SimOS::terminateThreadGroup(uint64_t tgid) {
  auto proc = processes_.begin();
  while (proc != processes_.end()) {
    if (proc->second->getTGID() == tgid) {
      // If clear_chilt_tid is non-zero then write 0 to this address
      uint64_t addr = proc->second->clearChildTid_;
      if (addr) {
        memory_->sendUntimedData({0}, addr, 1);
        // TODO: When `futex` has been implemented, perform
        // futex(clear_child_tid, FUTEX_WAKE, 1, NULL, NULL, 0);
      }
      // Set status to complete so it can be removed from the relevant queue in
      // tick()
      proc->second->status_ = procStatus::completed;
      proc = processes_.erase(proc);
    } else {
      proc++;
    }
  }
  // Remove all FutexInfo structs assosciated with processes with TGID = `tgid`
  syscallHandler_->removeFutexInfoList(tgid);
}

uint64_t SimOS::requestPageFrames(size_t size) {
  return pageFrameAllocator_.allocate(size);
}

uint64_t SimOS::handleVAddrTranslation(uint64_t vaddr, uint64_t tid) {
  auto process = processes_.find(0)->second;
  uint64_t translation = process->pageTable_->translate(vaddr);
  uint64_t faultCode = masks::faults::getFaultCode(translation);

  // Return the translation if faultCode is not translate, any other faults
  // will be handled further. Only page faults will be handled here.
  if (faultCode != masks::faults::pagetable::TRANSLATE) return translation;

  uint64_t addr = process->handlePageFault(vaddr);
  faultCode = masks::faults::getFaultCode(addr);

  if (faultCode == masks::faults::pagetable::MAP) {
    std::cerr << "[SimEng:SimOS] Failed to create mapping during PageFault "
                 "caused by Vaddr: "
              << vaddr << "( TID: " << tid << " )" << std::endl;
    std::exit(1);
  }

  return addr;
}

VAddrTranslator SimOS::getVAddrTranslator() {
  auto fn = [this](uint64_t vaddr, uint64_t pid) -> uint64_t {
    return handleVAddrTranslation(vaddr, pid);
  };
  return fn;
}

void SimOS::createSpecialFileDirectory() const {
  simeng::SpecialFileDirGen SFdir = simeng::SpecialFileDirGen();
  // Remove any current special files dir
  SFdir.RemoveExistingSFDir();
  // Create new special files dir
  SFdir.GenerateSFDir();
}

uint64_t SimOS::getSystemTimer() const {
  // TODO: This will need to be changed if we start supporting DVFS (Dynamic
  // voltage and frequency scaling).
  return ticks_ /
         ((Config::get()["Core"]["Clock-Frequency"].as<float>() * 1e9) / 1e9);
}

void SimOS::receiveSyscall(SyscallInfo syscallInfo) const {
  syscallHandler_->receiveSyscall(syscallInfo);
}

void SimOS::sendSyscallResult(const SyscallResult result) const {
  cores_[result.coreId]->receiveSyscallResult(result);
}

}  // namespace OS
}  // namespace simeng
