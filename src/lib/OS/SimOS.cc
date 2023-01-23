#include "simeng/OS/SimOS.hh"

#include "simeng/kernel/Masks.hh"

/** The size of each time slice a process has. */
static constexpr uint64_t execTicks = 30000;

namespace simeng {
namespace OS {

SimOS::SimOS(std::string executablePath,
             std::vector<std::string> executableArgs,
             std::shared_ptr<simeng::memory::Mem> mem, bool setProcess)
    : executablePath_(executablePath),
      executableArgs_(executableArgs),
      memory_(mem),
      syscallHandler_(std::make_shared<SyscallHandler>(processes_)) {
  sendToMem_ = [&, this](char* data, uint64_t addr, size_t size) {
    this->memory_->sendUntimedData(data, addr, size);
  };
  pageFrameAllocator_ = std::make_shared<PageFrameAllocator>();
  if (!setProcess) createInitialProcess();

  // Create the Special Files directory if indicated to do so in Config file
  if (Config::get()["CPU-Info"]["Generate-Special-Dir"].as<bool>() == true)
    createSpecialFileDirectory();
}

void SimOS::tick() {
  // Check if simulation halted
  if (halted_) {
    return;
  }

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
   * core
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
        if (!scheduledProcs_.empty()) {
          // Get context of process that was executing on core
          OS::cpuContext prevContext = core->getPrevContext();
          // Core's stored TID will equal -1 if no process has been previously
          // scheduled (i.e. on first tick of simulation)
          if (prevContext.TID != -1) {
            // Find the corresponding process in map
            auto proc = processes_.find(prevContext.TID)->second;
            assert(
                (proc->status_ == procStatus::executing) &&
                "[SimEng:SimOS] Process updated when not in executing state.");
            // Only update values which have changed
            proc->context_.pc = prevContext.pc;
            proc->context_.regFile = prevContext.regFile;
            // Change status from Executing to Waiting
            proc->status_ = procStatus::waiting;
            waitingProcs_.push(proc);
          }

          // Schedule new process on core
          core->schedule(scheduledProcs_.front()->context_);
          // Update newly scheduled process' status
          scheduledProcs_.front()->status_ = procStatus::executing;
          // Remove process from waiting queue
          scheduledProcs_.pop();
        }
        break;
      }
      case CoreStatus::executing: {
        // Core is executing, test if interrupt should be made
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

const Process& SimOS::getProcess(uint64_t TID) const {
  auto proc = processes_.find(TID);
  if (proc == processes_.end()) {
    // If TID doesn't exist then hard exit
    std::cerr << "[SimEng:SimOS] ERROR : Process with TID `" << TID
              << "` does not exist.\n";
    exit(1);
  }
  return (*proc->second);
}

void SimOS::createInitialProcess() {
  // TODO : When supporting multiple processes, need to keep track of next
  // available TGID and TIDs, and pass these when constructing a Process
  // object

  // Temporarily create the architecture, with knowledge of the OS
  std::unique_ptr<simeng::arch::Architecture> arch;
  if (Config::get()["Core"]["ISA"].as<std::string>() == "rv64") {
    arch = std::make_unique<simeng::arch::riscv::Architecture>(syscallHandler_);
  } else if (Config::get()["Core"]["ISA"].as<std::string>() == "AArch64") {
    arch =
        std::make_unique<simeng::arch::aarch64::Architecture>(syscallHandler_);
  }

  // Get structure of Architectural register file
  std::vector<RegisterFileStructure> regFileStructure =
      arch->getRegisterFileStructures();

  if (executablePath_ != DEFAULT_STR) {
    // Concatenate the command line arguments into a single vector and create
    // the process image
    std::vector<std::string> commandLine = {executablePath_};
    commandLine.insert(commandLine.end(), executableArgs_.begin(),
                       executableArgs_.end());

    processes_.emplace(0, std::make_shared<Process>(commandLine, memory_,
                                                    regFileStructure, 0, 0));

    // Raise error if created process is not valid
    if (!processes_[0]->isValid()) {
      std::cerr << "[SimEng:SimOS] Could not read/parse " << commandLine[0]
                << std::endl;
      exit(1);
    }
  } else {
    // Create a process image from the set of instructions held in hex_
    processes_.emplace(
        0, std::make_shared<Process>(
               simeng::span<char>(reinterpret_cast<char*>(hex_), sizeof(hex_)),
               memory_, regFileStructure, 0, 0));
    // Raise error if created process is not valid
    if (!processes_[0]->isValid()) {
      std::cerr << "[SimEng:SimOS] Could not create initial process based on "
                   "supplied instruction span"
                << std::endl;
      exit(1);
    }
  }
  assert(processes_[0]->isValid() &&
         "[SimEng:SimOS] Attempted to use an invalid process");

  // Set Initial state of registers
  if (Config::get()["Core"]["ISA"].as<std::string>() == "rv64") {
    processes_[0]->context_.regFile[arch::riscv::RegisterType::GENERAL][2] = {
        processes_[0]->context_.sp, 8};
  } else if (Config::get()["Core"]["ISA"].as<std::string>() == "AArch64") {
    // Set the stack pointer register
    processes_[0]->context_.regFile[arch::aarch64::RegisterType::GENERAL][31] =
        {processes_[0]->context_.sp, 8};
    // Set the system registers
    // Temporary: state that DCZ can support clearing 64 bytes at a time,
    // but is disabled due to bit 4 being set
    processes_[0]->context_.regFile[arch::aarch64::RegisterType::SYSTEM]
                                   [arch->getSystemRegisterTag(
                                       ARM64_SYSREG_DCZID_EL0)] = {
        static_cast<uint64_t>(0b10100), 8};
  }

  // In a simulation's initial state, all cores will be idle. Only 'scheduled'
  // processes may be sent to a core for execution therefore we must update
  // the initial processes status and push it to the scheduledProcs queue
  processes_[0]->status_ = procStatus::scheduled;
  scheduledProcs_.push(processes_[0]);
}

void SimOS::createSpecialFileDirectory() const {
  simeng::SpecialFileDirGen SFdir = simeng::SpecialFileDirGen();
  // Remove any current special files dir
  SFdir.RemoveExistingSFDir();
  // Create new special files dir
  SFdir.GenerateSFDir();
}

uint64_t SimOS::requestPageFrames(size_t size) {
  return pageFrameAllocator_->allocate(size);
}

uint64_t SimOS::handleVAddrTranslation(uint64_t vaddr, uint64_t pid) {
  // Since SimEng in single core currently, we don't need to worry about
  // multiple pprocessses.
  auto process = processes_[0];
  uint64_t translation = process->pageTable_->translate(vaddr);
  uint64_t faultCode = masks::faults::getFaultCode(translation);
  if (!(faultCode == masks::faults::pagetable::translate)) return translation;

  uint64_t addr = process->handlePageFault(vaddr, sendToMem_);
  faultCode = masks::faults::getFaultCode(addr);

  if (faultCode == masks::faults::pagetable::map) {
    std::cerr << "Failed to create mapping during PageFault caused by Vaddr: "
              << vaddr << "( PID: " << pid << " )" << std::endl;
    std::exit(1);
  }

  return addr;
}

VAddrTranslator SimOS::getVAddrTranslator() {
  auto fn = [&, this](uint64_t vaddr, uint64_t pid) -> uint64_t {
    return this->handleVAddrTranslation(vaddr, pid);
  };
  return fn;
}

}  // namespace OS
}  // namespace simeng
