#include "simeng/CoreInstance.hh"

#include <unistd.h>

namespace simeng {

CoreInstance::CoreInstance(std::string executablePath,
                           std::vector<std::string> executableArgs) {
  config_ = YAML::Load(DEFAULT_CONFIG);
  generateCoreModel(executablePath, executableArgs);
}

CoreInstance::CoreInstance(std::string configPath, std::string executablePath,
                           std::vector<std::string> executableArgs) {
  config_ = simeng::ModelConfig(configPath).getConfigFile();
  generateCoreModel(executablePath, executableArgs);
}

CoreInstance::CoreInstance(char* assembledSource, size_t sourceSize,
                           std::string configPath) {
  config_ = simeng::ModelConfig(configPath).getConfigFile();
  source_ = assembledSource;
  sourceSize_ = sourceSize;
  assembledSource_ = true;
  // Pass an empty string for executablePath and empty vector of strings for
  // executableArgs.
  generateCoreModel("", std::vector<std::string>{});
}

CoreInstance::~CoreInstance() {
  if (source_) {
    delete[] source_;
  }
}

void CoreInstance::generateCoreModel(std::string executablePath,
                                     std::vector<std::string> executableArgs) {
  setSimulationMode();
  createProcess(executablePath, executableArgs);
  // Check to see if either of the instruction or data memory interfaces should
  // be created. Don't create the core if either interface is marked as External
  // as they must be set manually prior to the core's creation.

  // Convert Data-Memory's Interface-Type value from a string to
  // simeng::MemInterfaceType
  std::string dType_string =
      config_["L1-Data-Memory"]["Interface-Type"].as<std::string>();
  simeng::MemInterfaceType dType = simeng::MemInterfaceType::Flat;
  if (dType_string == "Fixed") {
    dType = simeng::MemInterfaceType::Fixed;
  } else if (dType_string == "External") {
    dType = simeng::MemInterfaceType::External;
  }
  // Create data memory if appropriate
  if (dType == simeng::MemInterfaceType::External) {
    setDataMemory_ = true;
  } else {
    createL1DataMemory(dType);
  }

  // Convert Instruction-Memory's Interface-Type value from a string to
  // simeng::MemInterfaceType
  std::string iType_string =
      config_["L1-Instruction-Memory"]["Interface-Type"].as<std::string>();
  simeng::MemInterfaceType iType = simeng::MemInterfaceType::Flat;
  if (iType_string == "Fixed") {
    iType = simeng::MemInterfaceType::Fixed;
  } else if (iType_string == "External") {
    iType = simeng::MemInterfaceType::External;
  }
  // Create instruction memory if appropriate
  if (iType == simeng::MemInterfaceType::External) {
    setInstructionMemory_ = true;
  } else {
    createL1InstructionMemory(iType);
  }

  // Create the core if neither memory interfaces are externally constructed
  if (!(setDataMemory_ || setInstructionMemory_)) createCore();

  // If the source program to simulate is a checkpoint file, read in relevant
  // checkpoint data
  if (config_["checkpointSource"].as<std::string>() != "") {
    std::ifstream readChk;
    readChk.open(config_["checkpointSource"].as<std::string>(),
                 std::ios::binary);
    // Skip magic numbers
    readChk.seekg(4, std::ios::cur);
    // Read in the number of sections
    uint8_t numSections;
    readChk.read(reinterpret_cast<char*>(&numSections), sizeof(numSections));

    // Search for section holding open FD checkpoint data
    bool foundSection = false;
    for (uint8_t section = 0; section < numSections; section++) {
      uint8_t sectionID;
      readChk.read(reinterpret_cast<char*>(&sectionID), sizeof(sectionID));
      if (sectionID == '\1') {
        foundSection = true;
        break;
      }
      // Skip offset value associated with unused section
      readChk.seekg(8, std::ios::cur);
    }

    if (foundSection) {
      // Read in and navigate to offset
      uint64_t offset;
      readChk.read(reinterpret_cast<char*>(&offset), sizeof(offset));
      readChk.seekg(offset);

      // Get the number of open FDs
      size_t numFDs;
      readChk.read(reinterpret_cast<char*>(&numFDs), sizeof(numFDs));

      for (size_t fd = 0; fd < numFDs; fd++) {
        // Read in FD information to parameterise `openat` call
        int64_t dirfd;
        readChk.read(reinterpret_cast<char*>(&dirfd), sizeof(dirfd));
        uint64_t fpOff;
        readChk.read(reinterpret_cast<char*>(&fpOff), sizeof(fpOff));
        size_t pathnameSize;
        readChk.read(reinterpret_cast<char*>(&pathnameSize),
                     sizeof(pathnameSize));
        std::string pathname(pathnameSize, '\0');
        readChk.read(&pathname[0], pathnameSize);
        int64_t flags;
        readChk.read(reinterpret_cast<char*>(&flags), sizeof(flags));
        uint16_t mode;
        readChk.read(reinterpret_cast<char*>(&mode), sizeof(mode));
        int64_t vfd = kernel_.openat(dirfd, pathname, flags, mode);
        // Set file pointer to that held in the checkpoint
        kernel_.lseek(vfd, fpOff, SEEK_SET);
      }
    }
    readChk.close();
  }

  return;
}

void CoreInstance::setSimulationMode() {
  // Get the simualtion mode as defined by the set configuration, defaulting to
  // emulation
  if (config_["Core"]["Simulation-Mode"].as<std::string>() ==
      "inorderpipelined") {
    mode_ = SimulationMode::InOrderPipelined;
    modeString_ = "In-Order Pipelined";
  } else if (config_["Core"]["Simulation-Mode"].as<std::string>() ==
             "outoforder") {
    mode_ = SimulationMode::OutOfOrder;
    modeString_ = "Out-of-Order";
  }

  return;
}

void CoreInstance::createProcess(std::string executablePath,
                                 std::vector<std::string> executableArgs) {
  if (executablePath.length() > 0) {
    // Concatenate the command line arguments into a single vector and create
    // the process image
    std::vector<std::string> commandLine = {executablePath};
    commandLine.insert(commandLine.end(), executableArgs.begin(),
                       executableArgs.end());
    process_ =
        std::make_unique<simeng::kernel::LinuxProcess>(commandLine, config_);

    // Raise error if created process is not valid
    if (!process_->isValid()) {
      std::cerr << "[SimEng:CoreInstance] Could not read/parse "
                << commandLine[0] << std::endl;
      exit(1);
    }
  } else if (assembledSource_) {
    // Create a process image from the source code assembled by LLVM.
    process_ = std::make_unique<simeng::kernel::LinuxProcess>(
        simeng::span<char>(source_, sourceSize_), config_);
    // Raise error if created process is not valid
    if (!process_->isValid()) {
      std::cerr << "[SimEng:CoreInstance] Could not create process based on "
                   "source assembled by LLVM"
                << std::endl;
      exit(1);
    }
  } else {
    // Create a process image from the set of instructions held in hex_
    process_ = std::make_unique<simeng::kernel::LinuxProcess>(
        simeng::span<char>(reinterpret_cast<char*>(hex_), sizeof(hex_)),
        config_);

    // Raise error if created process is not valid
    if (!process_->isValid()) {
      std::cerr << "[SimEng:CoreInstance] Could not create process based on "
                   "supplied instruction span"
                << std::endl;
      exit(1);
    }
  }

  // Create the process memory space from the generated process image
  createProcessMemory();

  // Create the OS kernel with the process
  kernel_.createProcess(*process_.get());

  return;
}

void CoreInstance::createProcessMemory() {
  // Get the process image and its size
  processMemory_ = process_->getProcessImage();
  processMemorySize_ = process_->getProcessImageSize();

  return;
}

void CoreInstance::createL1InstructionMemory(
    const simeng::MemInterfaceType type) {
  // Create a L1I cache instance based on type supplied
  if (type == simeng::MemInterfaceType::Flat) {
    instructionMemory_ = std::make_shared<simeng::FlatMemoryInterface>(
        processMemory_.get(), processMemorySize_);
  } else if (type == simeng::MemInterfaceType::Fixed) {
    instructionMemory_ = std::make_shared<simeng::FixedLatencyMemoryInterface>(
        processMemory_.get(), processMemorySize_,
        config_["LSQ-L1-Interface"]["Access-Latency"].as<uint16_t>());
  } else {
    std::cerr
        << "[SimEng:CoreInstance] Unsupported memory interface type used in "
           "createL1InstructionMemory()."
        << std::endl;
    exit(1);
  }

  return;
}

void CoreInstance::setL1InstructionMemory(
    std::shared_ptr<simeng::MemoryInterface> memRef) {
  assert(setInstructionMemory_ &&
         "setL1InstructionMemory(...) called but the interface was created by "
         "the CoreInstance class.");
  // Set the L1I cache instance to use
  instructionMemory_ = memRef;
  return;
}

void CoreInstance::createL1DataMemory(const simeng::MemInterfaceType type) {
  // Create a L1D cache instance based on type supplied
  if (type == simeng::MemInterfaceType::Flat) {
    dataMemory_ = std::make_shared<simeng::FlatMemoryInterface>(
        processMemory_.get(), processMemorySize_);
  } else if (type == simeng::MemInterfaceType::Fixed) {
    dataMemory_ = std::make_shared<simeng::FixedLatencyMemoryInterface>(
        processMemory_.get(), processMemorySize_,
        config_["LSQ-L1-Interface"]["Access-Latency"].as<uint16_t>());
  } else {
    std::cerr << "[SimEng:CoreInstance] Unsupported memory interface type used "
                 "in createL1DataMemory()."
              << std::endl;
    exit(1);
  }

  return;
}

void CoreInstance::setL1DataMemory(
    std::shared_ptr<simeng::MemoryInterface> memRef) {
  assert(setDataMemory_ &&
         "setL1DataMemory(...) called but the interface was created by the "
         "CoreInstance class.");
  // Set the L1D cache instance to use
  dataMemory_ = memRef;
  return;
}

void CoreInstance::createCore() {
  // If memory interfaces must be manually set, ensure they have been
  if (setDataMemory_ && (dataMemory_ == nullptr)) {
    std::cerr << "[SimEng:CoreInstance] Data memory not set. External Data "
                 "memory must be manually "
                 "set using the setL1DataMemory(...) function."
              << std::endl;
    exit(1);
  } else if (setInstructionMemory_ && (instructionMemory_ == nullptr)) {
    std::cerr << "[SimEng:CoreInstance] Instruction memory not set. External "
                 "instruction memory "
                 "interface must be manually set using the "
                 "setL1InstructionMemory(...) function."
              << std::endl;
    exit(1);
  }

  // Create the architecture, with knowledge of the kernel
  if (config_["Core"]["ISA"].as<std::string>() == "rv64") {
    arch_ =
        std::make_unique<simeng::arch::riscv::Architecture>(kernel_, config_);
  } else if (config_["Core"]["ISA"].as<std::string>() == "AArch64") {
    arch_ =
        std::make_unique<simeng::arch::aarch64::Architecture>(kernel_, config_);
  }

  // Construct branch predictor object
  predictor_ = std::make_unique<simeng::GenericPredictor>(config_);

  // Extract port arrangement from config file
  auto config_ports = config_["Ports"];
  std::vector<std::vector<uint16_t>> portArrangement(config_ports.size());
  for (size_t i = 0; i < config_ports.size(); i++) {
    auto config_groups = config_ports[i]["Instruction-Group-Support"];
    // Read groups in associated port
    for (size_t j = 0; j < config_groups.size(); j++) {
      portArrangement[i].push_back(config_groups[j].as<uint16_t>());
    }
  }
  portAllocator_ = std::make_unique<simeng::pipeline::BalancedPortAllocator>(
      portArrangement);

  // Construct the core object based on the defined simulation mode
  uint64_t entryPoint = process_->getEntryPoint();
  if (mode_ == SimulationMode::Emulation) {
    core_ = std::make_shared<simeng::models::emulation::Core>(
        *instructionMemory_, *dataMemory_, entryPoint, processMemorySize_,
        *arch_, config_);
  } else if (mode_ == SimulationMode::InOrderPipelined) {
    core_ = std::make_shared<simeng::models::inorder::Core>(
        *instructionMemory_, *dataMemory_, processMemorySize_, entryPoint,
        *arch_, *predictor_, config_);
  } else if (mode_ == SimulationMode::OutOfOrder) {
    core_ = std::make_shared<simeng::models::outoforder::Core>(
        *instructionMemory_, *dataMemory_, processMemorySize_, entryPoint,
        *arch_, *predictor_, *portAllocator_, config_);
  }

  createSpecialFileDirectory();

  return;
}

void CoreInstance::createSpecialFileDirectory() {
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

const SimulationMode CoreInstance::getSimulationMode() const { return mode_; }

const std::string CoreInstance::getSimulationModeString() const {
  return modeString_;
}

std::shared_ptr<simeng::Core> CoreInstance::getCore() const {
  if (core_ == nullptr) {
    std::cerr
        << "[SimEng:CoreInstance] Core object not constructed. If either data "
           "or instruction memory "
           "interfaces are marked as an `External` type, they must be set "
           "manually and then core's creation must be called manually."
        << std::endl;
    exit(1);
  }
  return core_;
}

std::shared_ptr<simeng::MemoryInterface> CoreInstance::getDataMemory() const {
  if (setDataMemory_ && (dataMemory_ == nullptr)) {
    std::cerr << "[SimEng:CoreInstance] `External` data memory object not set."
              << std::endl;
    exit(1);
  }
  return dataMemory_;
}

std::shared_ptr<simeng::MemoryInterface> CoreInstance::getInstructionMemory()
    const {
  if (setInstructionMemory_ && (instructionMemory_ == nullptr)) {
    std::cerr
        << "`[SimEng:CoreInstance] External` instruction memory object not set."
        << std::endl;
    exit(1);
  }
  return instructionMemory_;
}

std::shared_ptr<char> CoreInstance::getProcessImage() const {
  return processMemory_;
}

const uint64_t CoreInstance::getProcessImageSize() const {
  return processMemorySize_;
}

const uint64_t CoreInstance::getHeapStart() const {
  return process_->getHeapStart();
};

template <typename T>
void CoreInstance::writeToCheckpoint(T value) {
  if (!chkPnt_.is_open()) {
    std::cerr << "[SimEng:CoreInstance] Tried to write to the checkpoint file "
                 "which is not open."
              << std::endl;
    exit(1);
  }
  // Write to the checkpoint file byte-by-byte to ensure value can be read back
  // correctly
  for (int byte = 0; byte < sizeof(value); byte++) {
    chkPnt_ << static_cast<char>((value & (0xffull << (byte * 8))) >>
                                 (byte * 8));
  }
}

void CoreInstance::checkpoint() {
  chkPnt_.open(config_["Core"]["checkpointOutput"].as<std::string>());

  // Write magic numbers ('S'im'E'ng 'C'heck'P'oint) to checkpoint file for
  // later identification of file type
  chkPnt_ << "SECP";

  // Calculate size of register fileset
  std::vector<RegisterFileStructure> regFileStructs =
      arch_->getRegisterFileStructures();
  uint64_t regFileSetBytes = 0;
  for (uint8_t type = 0; type < regFileStructs.size(); type++) {
    regFileSetBytes +=
        regFileStructs[type].bytes * regFileStructs[type].quantity;
  }
  // Calculate size of open FDs information
  std::vector<kernel::openFDParams> fileDescriptorTable = kernel_.getOpenFDs();
  uint64_t openFDsBytes = 0;
  size_t numOpenFDs = 0;
  for (const auto& fd : fileDescriptorTable) {
    if (fd.hfd == STDIN_FILENO || fd.hfd == STDOUT_FILENO ||
        fd.hfd == STDERR_FILENO || fd.hfd == -1)
      continue;
    openFDsBytes += 3 * sizeof(int64_t) + sizeof(uint16_t) + sizeof(size_t) +
                    fd.pathname.size();
    numOpenFDs++;
  }

  // Write checkpoint file section offsets. Each offset is comprised of a
  // uint8_t id and a uin64_t offset. With the 4 magic numbers and uint8_t value
  // denoting the number of section, the first section content is written at an
  // offset of (9 * numSections) + 5 bytes
  uint8_t numSections = 3 + (openFDsBytes == 0 ? 0 : 1);
  uint64_t sectionStart = (9 * numSections) + 5;
  // Write number of sections in file
  writeToCheckpoint(numSections);

  // Register file set
  chkPnt_ << '\0';
  writeToCheckpoint(sectionStart);
  sectionStart += regFileSetBytes;

  // Open FDs
  if (openFDsBytes != 0) {
    chkPnt_ << '\1';
    writeToCheckpoint(sectionStart);
    sectionStart += openFDsBytes;
    sectionStart += sizeof(size_t);
  }

  // Process Image
  chkPnt_ << '\2';
  writeToCheckpoint(sectionStart);
  uint64_t imageSize = process_->getProcessImageSize();
  sectionStart += 6 * sizeof(uint64_t) + imageSize;

  // Core statistics
  chkPnt_ << '\3';
  writeToCheckpoint(sectionStart);

  // Write registers
  std::cout << std::endl;
  std::cout << "[SimEng:CoreInstance] Generating Checkpoint..." << std::endl;
  std::cout << "[SimEng:CoreInstance] Checkpointing registers..." << std::endl;
  for (uint8_t type = 0; type < regFileStructs.size(); type++) {
    for (uint16_t tag = 0; tag < regFileStructs[type].quantity; tag++) {
      const uint8_t* regVal = core_->getArchitecturalRegisterFileSet()
                                  .get({type, tag})
                                  .getAsVector<uint8_t>();
      for (int byte = 0; byte < regFileStructs[type].bytes; byte++) {
        chkPnt_ << regVal[byte];
      }
    }
  }

  // Write information for open FDs
  std::cout << "[SimEng:CoreInstance] Checkpointing open FDs..." << std::endl;
  writeToCheckpoint(numOpenFDs);
  for (const auto& fd : fileDescriptorTable) {
    // If the FD is for STDIN, STDOUT or STDERR, don't write to the checkpoint
    // file as we implicitly open these FDs when starting the simulation
    if (fd.hfd == STDIN_FILENO || fd.hfd == STDOUT_FILENO ||
        fd.hfd == STDERR_FILENO || fd.hfd == -1)
      continue;
    writeToCheckpoint(fd.dfd);
    // Get the current file pointer offset so we can correctly restore the state
    // of the open FD
    FILE* openFD = fdopen(fd.hfd, "rb");
    uint64_t fPntrOff = ftell(openFD);
    writeToCheckpoint(fPntrOff);
    writeToCheckpoint(fd.pathname.size());
    for (int byte = 0; byte < fd.pathname.size(); byte++) {
      chkPnt_ << fd.pathname.c_str()[byte];
    }
    writeToCheckpoint(fd.flags);
    writeToCheckpoint(fd.mode);
  }

  // Write process image structure variables
  std::cout << "[SimEng:CoreInstance] Checkpointing ProcessImage..."
            << std::endl;
  writeToCheckpoint(process_->getHeapStart());
  writeToCheckpoint(process_->getMmapStart());
  writeToCheckpoint(core_->getExecPC());
  writeToCheckpoint(process_->getStackPointer());
  writeToCheckpoint(kernel_.brk(0));
  writeToCheckpoint(imageSize);

  // Write process image memory content
  float progress = 0.01;
  double printThreshold = 0;
  char* memory = process_->getProcessImage().get();
  for (uint64_t byte = 0; byte < imageSize; byte++) {
    chkPnt_ << memory[byte];
    // Write a progress bar to the STDOUT
    if (double(byte) > printThreshold) {
      printThreshold += double(imageSize) * 0.01;
      progress += 0.01;
      std::cout.flush();
      std::cout << "[";
      int pos = 100 * progress;
      for (int i = 0; i < 100; ++i) {
        if (i < pos)
          std::cout << "=";
        else if (i == pos)
          std::cout << ">";
        else
          std::cout << " ";
      }
      std::cout << "] " << int(progress * 100.0) << "% \r";
    }
  }
  std::cout << std::endl;

  // Write core statistics
  std::cout << "[SimEng:CoreInstance] Checkpointing Core "
               "statistics..."
            << std::endl;
  writeToCheckpoint(core_->getElapsedTicks());

  chkPnt_.close();
}
}  // namespace simeng
