#include "simeng/CoreInstance.hh"

namespace simeng {

CoreInstance::CoreInstance(int argc, char** argv) {
  config_ = YAML::Load(DEFAULT_CONFIG);
  generateCoreModel(argc, argv);
}

CoreInstance::CoreInstance(int argc, char** argv, std::string configPath) {
  config_ = simeng::ModelConfig(configPath).getConfigFile();
  generateCoreModel(argc, argv);
}

CoreInstance::~CoreInstance() {}

void CoreInstance::generateCoreModel(int argc, char** argv) {
  setSimulationMode();
  createProcess(argc, argv);
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
    manualCreateCore_ = true;
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
    manualCreateCore_ = true;
    setInstructionMemory_ = true;
  } else {
    createL1InstructionMemory(iType);
  }

  // Create the core if neither memory interfaces are externally constructed
  if (!manualCreateCore_) createCore();

  return;
}

void CoreInstance::setSimulationMode() {
  // Get the simualtion mode as defined by the set configuration, defaulting to
  // emulation
  if (config_["Core"]["Simulation-Mode"].as<std::string>() ==
      "inorderpipelined") {
    mode_ = SimulationMode::InOrderPipelined;
  } else if (config_["Core"]["Simulation-Mode"].as<std::string>() ==
             "outoforder") {
    mode_ = SimulationMode::OutOfOrder;
  }
}

void CoreInstance::createProcess(int argc, char** argv) {
  // Check for passed executable
  std::string executablePath = "";
  if (argc != 0) {
    executablePath = std::string(argv[0]);
  }

  if (executablePath.length() > 0) {
    // Attempt to create the process image from the specified command-line
    std::vector<std::string> commandLine(argv, argv + argc);
    process_ =
        std::make_unique<simeng::kernel::LinuxProcess>(commandLine, config_);

    // Raise error if created process is not valid
    if (!process_->isValid()) {
      std::cerr << "Could not read/parse " << commandLine[0] << std::endl;
      exit(1);
    }
  } else {
    process_ = std::make_unique<simeng::kernel::LinuxProcess>(
        simeng::span<char>(reinterpret_cast<char*>(hex_), sizeof(hex_)),
        config_);

    // Raise error if created process is not valid
    if (!process_->isValid()) {
      std::cerr << "Could not create process based on supplied instruction span"
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
    std::cerr << "Unsupported memory interface type used in "
                 "createL1InstructionMemory()."
              << std::endl;
    exit(1);
  }

  return;
}

void CoreInstance::setL1InstructionMemory(
    std::shared_ptr<simeng::MemoryInterface> memRef) {
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
    std::cerr
        << "Unsupported memory interface type used in createL1DataMemory()."
        << std::endl;
    exit(1);
  }

  return;
}

void CoreInstance::setL1DataMemory(
    std::shared_ptr<simeng::MemoryInterface> memRef) {
  // Set the L1D cache instance to use
  dataMemory_ = memRef;
  return;
}

void CoreInstance::createCore() {
  // If memory interfaces must be manually set, ensure they have been
  if (setDataMemory_ && (dataMemory_ == nullptr)) {
    std::cerr << "Data memory not set. External Data memory must be manually "
                 "set using the setL1DataMemory(...) function."
              << std::endl;
    exit(1);
  } else if (setInstructionMemory_ && (instructionMemory_ == nullptr)) {
    std::cerr << "Instruction memory not set. External instruction memory "
                 "interface must be manually set using the "
                 "setL1InstructionMemory(...) function."
              << std::endl;
    exit(1);
  }

  // Construct architecture object
  arch_ =
      std::make_unique<simeng::arch::aarch64::Architecture>(kernel_, config_);

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

  // Configure reservation station arrangment
  std::vector<std::pair<uint8_t, uint64_t>> rsArrangement;
  for (size_t i = 0; i < config_["Reservation-Stations"].size(); i++) {
    // Iterate over each reservation station in config
    auto reservation_station = config_["Reservation-Stations"][i];
    for (size_t j = 0; j < reservation_station["Ports"].size(); j++) {
      // Iterate over issue ports in reservation station
      uint8_t port = reservation_station["Ports"][j].as<uint8_t>();
      if (rsArrangement.size() < port + 1) {
        // Resize vector to match number of execution ports available across
        // all reservation stations
        rsArrangement.resize(port + 1);
      }
      // Map an execution port to a reservation station
      rsArrangement[port] = {i, reservation_station["Size"].as<uint16_t>()};
    }
  }

  // Construct the core object based on the defined simulation mode
  uint64_t entryPoint = process_->getEntryPoint();
  if (mode_ == SimulationMode::Emulation) {
    core_ = std::make_shared<simeng::models::emulation::Core>(
        *instructionMemory_, *dataMemory_, entryPoint, processMemorySize_,
        *arch_);
  } else if (mode_ == SimulationMode::InOrderPipelined) {
    core_ = std::make_shared<simeng::models::inorder::Core>(
        *instructionMemory_, *dataMemory_, processMemorySize_, entryPoint,
        *arch_, *predictor_);
  } else if (mode_ == SimulationMode::OutOfOrder) {
    core_ = std::make_shared<simeng::models::outoforder::Core>(
        *instructionMemory_, *dataMemory_, processMemorySize_, entryPoint,
        *arch_, *predictor_, *portAllocator_, rsArrangement, config_);
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

std::shared_ptr<simeng::Core> CoreInstance::getCore() const {
  if (manualCreateCore_ && (core_ == nullptr)) {
    std::cerr << "Core object not constructed and marked as needed to be "
                 "manually created via the createCore() function. If either "
                 "data or instruction memory interfaces are marked as an "
                 "`External` type, they must be set manually and then core's "
                 "creation must be called manually."
              << std::endl;
    exit(1);
  }
  return core_;
}

std::shared_ptr<simeng::MemoryInterface> CoreInstance::getDataMemory() const {
  if (setDataMemory_ && (dataMemory_ == nullptr)) {
    std::cerr << "`External` data memory object not set." << std::endl;
    exit(1);
  }
  return dataMemory_;
}

std::shared_ptr<simeng::MemoryInterface> CoreInstance::getInstructionMemory()
    const {
  if (setInstructionMemory_ && (instructionMemory_ == nullptr)) {
    std::cerr << "`External` instruction memory object not set." << std::endl;
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

}  // namespace simeng
