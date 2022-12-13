#include "simeng/kernel/SimOS.hh"

namespace simeng {
namespace kernel {

SimOS::SimOS(int argc, char** argv)
    : syscallHandler_(SyscallHandler(processStates_)) {
  // Determine if a config file has been supplied.
  if (argc > 1) {
    config_ = simeng::ModelConfig(std::string(argv[1])).getConfigFile();
    // Determine if an executable has been supplied
    if (argc > 2) {
      executablePath_ = std::string(argv[2]);
      // Create a vector of any potential executable arguments from their
      // relative position within the argv variable
      int numberofArgs = argc - 3;
      executableArgs_ =
          std::vector<std::string>((argv + 3), (argv + 3) + numberofArgs);
    }
  } else {
    config_ = YAML::Load(DEFAULT_CONFIG);
  }
  createInitialProcess();
  createSpecialFileDirectory();
}

void SimOS::createInitialProcess() {
  std::shared_ptr<Process> newProcess;
  if (executablePath_ != DEFAULT_PATH) {
    // Concatenate the command line arguments into a single vector and create
    // the process image
    std::vector<std::string> commandLine = {executablePath_};
    commandLine.insert(commandLine.end(), executableArgs_.begin(),
                       executableArgs_.end());

    newProcess = std::make_shared<Process>(commandLine, config_);

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
        config_);

    // Raise error if created process is not valid
    if (!newProcess->isValid()) {
      std::cerr << "[SimEng:SimOS] Could not create initial process based on "
                   "supplied instruction span"
                << std::endl;
      exit(1);
    }
  }

  assert(newProcess.isValid() && "Attempted to use an invalid process");
  assert(processStates_.size() == 0 && "Multiple processes not yet supported");
  processStates_.push_back(
      {.pid = nextPid_,  // TODO: create unique PIDs
       .path = newProcess->getPath(),
       .startBrk = newProcess->getHeapStart(),
       .currentBrk = newProcess->getHeapStart(),
       .initialStackPointer = newProcess->getStackPointer(),
       .mmapRegion = newProcess->getMmapStart(),
       .pageSize = newProcess->getPageSize()});
  processStates_.back().fileDescriptorTable.push_back(STDIN_FILENO);
  processStates_.back().fileDescriptorTable.push_back(STDOUT_FILENO);
  processStates_.back().fileDescriptorTable.push_back(STDERR_FILENO);
  processes_.emplace_back(newProcess);
  nextPid_++;
}

std::shared_ptr<Process> SimOS::getProcess() {
  // TODO : update to search through Processes and match PID value
  return processes_[0];
}

void SimOS::createSpecialFileDirectory() {
  // Create the Special Files directory if indicated to do so in Config
  if (config_["CPU-Info"]["Generate-Special-Dir"].as<bool>() == true) {
    simeng::SpecialFileDirGen SFdir = simeng::SpecialFileDirGen(config_);
    // Remove any current special files dir
    SFdir.RemoveExistingSFDir();
    // Create new special files dir
    SFdir.GenerateSFDir();
  }

  return;
}

}  // namespace kernel
}  // namespace simeng