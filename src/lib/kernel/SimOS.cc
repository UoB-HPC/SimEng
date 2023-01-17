#include "simeng/kernel/SimOS.hh"

/** The size of each time slice a process has. */
static constexpr uint64_t execTicks = 30000;

namespace simeng {
namespace kernel {

SimOS::SimOS(int argc, char** argv, std::shared_ptr<simeng::memory::Mem> mem)
    : memory_(mem),
      syscallHandler_(std::make_shared<SyscallHandler>(processes_)) {
  // Parse command line args
  // Determine if a config file has been supplied.
  if (argc > 1) {
    // Set global config file to one at file path defined
    Config::set(std::string(argv[1]));

    // Determine if an executable has been supplied
    if (argc > 2) {
      executablePath_ = std::string(argv[2]);
      // Create a vector of any potential executable arguments from their
      // relative position within the argv variable
      int numberofArgs = argc - 3;
      executableArgs_ =
          std::vector<std::string>((argv + 3), (argv + 3) + numberofArgs);
    }
  }

  createInitialProcess();

  // Create the Special Files directory if indicated to do so in Config file
  if (Config::get()["CPU-Info"]["Generate-Special-Dir"].as<bool>() == true)
    createSpecialFileDirectory();
}

void SimOS::tick() {
  // Check for empty processes_ vector
  if (processes_.size() == 0) {
    halted_ = true;
    return;
  }

  // Check if any cores have halted
  for (auto i : cores_) {
    if (i->getStatus() == CoreStatus::halted) {
      // Core has experienced a fatal exception, halt simulation
      halted_ = true;
      return;
    }
  }

  /** Scheduling behaviour :
   * 1. All processes start in a waiting state, and are placed in the
   * 'waitingProc' queue.
   *
   * 2. All cores are looped over, checking their status. If there is a process
   * in the waitingProc queue then currently executing cores will be tested to
   * see if they should perform a context switch (Each Process is given X cycles
   * at a time; round-robin style).
   *
   * 3. If a core is sent an interupt signal, the head of waitingProcs queue is
   * put into scheduled queue.
   *
   * 4. Idle cores can only be scheduled processes from the scheduledProcs
   * queue.
   *
   * 5. When a process is successfully scheduled, it is removed from the
   * scheduledProcs queue.
   *
   * 6. When a process goes back into a waiting state (post context switch) it
   * will be pushed to the back of the waitingProcs queue.
   *
   * This ensures that multiple cores will not be interupted for a single
   * process
   *    - an OoO core may be in the switching state for multiple cycles, in
   *      which time a waitingProc could tell more executing cores to context
   *      switch.
   */

  // Loop over all cores, apply correct behaviour based on state
  for (size_t cID = 0; cID < cores_.size(); cID++) {
    switch (cores_[cID]->getStatus()) {
      case CoreStatus::halted:
        // Core has had fatal fault. Change SimOS status and return
        halted_ = true;
        return;
      case CoreStatus::idle:
        // Core is idle, schedule head of waitingProc queue
        //  - Get prevContext from core and update appropriate proc
        //  - Schedule waiting process on core
        //  - Update newly scheduled process' status
        //  - Remove process from waiting queue

        // TODO: update idle case
        cores_[cID]->schedule(scheduledProcs_.front()->context_);
        scheduledProcs_.pop();
      case CoreStatus::executing:
        // Core is executing, test if interupt should be made
        //  - If core has been running current process for X ticks, send
        //  interupt
      case CoreStatus::switching:
        // Core is currently preparing to switch process, do nothing this cycle
        break;
      case CoreStatus::exception:
        // Core currently processing syscall or exception, do nothing this cycle
        break;
    }
  }
}

Process SimOS::getProcess(uint64_t TID) const {
  for (auto i : processes_) {
    if (i->getTID() == TID) return (*i);
  }
  // If TID doesn't exist then hard exit
  std::cerr << "[SimEng:SimOS] ERROR : Process with TID `" << TID
            << "` does not exist.\n";
  exit(1);
}

void SimOS::createInitialProcess() {
  // Temporarily create the architecture, with knowledge of the kernel
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

  std::shared_ptr<Process> newProcess;
  if (executablePath_ != DEFAULT_STR) {
    // Concatenate the command line arguments into a single vector and create
    // the process image
    std::vector<std::string> commandLine = {executablePath_};
    commandLine.insert(commandLine.end(), executableArgs_.begin(),
                       executableArgs_.end());

    newProcess =
        std::make_shared<Process>(commandLine, memory_, regFileStructure);

    // Raise error if created process is not valid
    if (!newProcess->isValid()) {
      std::cerr << "[SimEng:CoreInstance] Could not read/parse "
                << commandLine[0] << std::endl;
      exit(1);
    }
    // IGNORE SST RELATED CASES FOR NOW
  } else {
    // Create a process image from the set of instructions held in hex_
    newProcess = std::make_shared<Process>(
        simeng::span<char>(reinterpret_cast<char*>(hex_), sizeof(hex_)),
        memory_, regFileStructure);

    // Raise error if created process is not valid
    if (!newProcess->isValid()) {
      std::cerr << "[SimEng:SimOS] Could not create initial process based on "
                   "supplied instruction span"
                << std::endl;
      exit(1);
    }
  }
  assert(newProcess->isValid() && "Attempted to use an invalid process");

  // Set Initial state of registers
  if (Config::get()["Core"]["ISA"].as<std::string>() == "rv64") {
    newProcess->context_.regFile[arch::riscv::RegisterType::GENERAL][2] = {
        newProcess->context_.sp, 8};
  } else if (Config::get()["Core"]["ISA"].as<std::string>() == "AArch64") {
    // Set the stack pointer register
    newProcess->context_.regFile[arch::aarch64::RegisterType::GENERAL][31] = {
        newProcess->context_.sp, 8};
    // Set the system registers
    // Temporary: state that DCZ can support clearing 64 bytes at a time,
    // but is disabled due to bit 4 being set
    newProcess->context_
        .regFile[arch::aarch64::RegisterType::SYSTEM]
                [arch->getSystemRegisterTag(ARM64_SYSREG_DCZID_EL0)] = {
        static_cast<uint64_t>(0b10100), 8};
  }

  processes_.emplace_back(newProcess);
  // In a simulation's initial state, all cores will be idle. Only 'scheduled'
  // processes may be sent to a core for execution therefore we must update the
  // initial processes status and push it to the scheduledProcs queue
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

}  // namespace kernel
}  // namespace simeng