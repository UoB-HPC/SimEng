#include "simeng/kernel/SimOS.hh"

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
    // TODO: Add halt functionality
  }

  // Check process status
  auto iter = processes_.begin();
  while (iter != processes_.end()) {
    if ((*iter)->status_ == completed) {
      // Remove finished processes
      iter = processes_.erase(iter);
      continue;
    }
    if ((*iter)->status_ == waiting) {
      // Try schedule waiting process
      for (auto i : cores_) {
        if (i->isIdle()) {
          // Schedule process with idle core
          i->schedule(*iter);
        } else {
          // Check how long current process has been executing.
          // If over threshold, interrupr core
          // TODO : Set up round robin scheduling.
        }
      }
    }
    iter++;
  }
}

std::shared_ptr<Process> SimOS::getProcess() const {
  // TODO : update to search through Processes and match PID value
  return processes_[0];
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
    newProcess->context_.regFile[arch::riscv::RegisterType::GENERAL][2] =
        newProcess->context_.sp;
  } else if (Config::get()["Core"]["ISA"].as<std::string>() == "AArch64") {
    // Set the stack pointer register
    newProcess->context_.regFile[arch::aarch64::RegisterType::GENERAL][31] =
        newProcess->context_.sp;
    // Set the system registers
    // Temporary: state that DCZ can support clearing 64 bytes at a time,
    // but is disabled due to bit 4 being set
    newProcess->context_
        .regFile[arch::aarch64::RegisterType::SYSTEM]
                [arch->getSystemRegisterTag(ARM64_SYSREG_DCZID_EL0)] =
        static_cast<uint64_t>(0b10100);
  }

  processes_.emplace_back(newProcess);
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