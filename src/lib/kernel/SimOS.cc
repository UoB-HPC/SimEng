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

std::shared_ptr<Process> SimOS::getProcess() const {
  // TODO : update to search through Processes and match PID value
  return processes_[0];
}

void SimOS::createInitialProcess() {
  std::shared_ptr<Process> newProcess;
  if (executablePath_ != DEFAULT_STR) {
    // Concatenate the command line arguments into a single vector and create
    // the process image
    std::vector<std::string> commandLine = {executablePath_};
    commandLine.insert(commandLine.end(), executableArgs_.begin(),
                       executableArgs_.end());

    newProcess = std::make_shared<Process>(commandLine, memory_);

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
        memory_);

    // Raise error if created process is not valid
    if (!newProcess->isValid()) {
      std::cerr << "[SimEng:SimOS] Could not create initial process based on "
                   "supplied instruction span"
                << std::endl;
      exit(1);
    }
  }
  assert(newProcess.isValid() && "Attempted to use an invalid process");
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