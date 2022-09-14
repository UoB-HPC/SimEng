#include "simeng/CoreInstance.hh"

namespace simeng {

CoreInstance::CoreInstance() {
  config_ = YAML::Load(DEFAULT_CONFIG);
  setSimulationMode();
}

CoreInstance::CoreInstance(std::string configPath) {
  config_ = simeng::ModelConfig(configPath).getConfigFile();
  setSimulationMode();
}

CoreInstance::CoreInstance(YAML::Node config) {
  config_ = config;
  setSimulationMode();
}

CoreInstance::~CoreInstance() {}

void CoreInstance::setSimulationMode() {
  // Get simualtion mode as defined by the set configuration
  if (config_["Core"]["Simulation-Mode"].as<std::string>() ==
      "inorderpipelined") {
    mode_ = SimulationMode::InOrderPipelined;
  } else if (config_["Core"]["Simulation-Mode"].as<std::string>() ==
             "outoforder") {
    mode_ = SimulationMode::OutOfOrder;
  }
}

void CoreInstance::createProcessMemory() {
  // Get the process image
  auto processImage = process_->getProcessImage();

  // Allocate a region of memory for the process memory
  processMemorySize_ = processImage.size();
  processMemory_ = new char[processMemorySize_]();

  // Fill the process memory with the generated process image
  std::copy(processImage.begin(), processImage.end(), processMemory_);
}

void CoreInstance::createProcess(const std::vector<std::string>& commandLine) {
  process_ =
      std::make_unique<simeng::kernel::LinuxProcess>(commandLine, config_);

  // Raise error if created process is not valid
  if (!process_->isValid()) {
    std::cerr << "Could not read/parse " << commandLine[0] << std::endl;
    exit(1);
  }

  // Create the process memory space from the generated process image
  createProcessMemory();

  // Create the OS kernel with the process
  kernel_.createProcess(*process_.get());

  return;
}

void CoreInstance::createProcess(span<char> instructions) {
  process_ =
      std::make_unique<simeng::kernel::LinuxProcess>(instructions, config_);

  // Raise error if created process is not valid
  if (!process_->isValid()) {
    std::cerr << "Could not create process based on supplied instruction span"
              << std::endl;
    exit(1);
  }

  // Create the process memory space from the generated process image
  createProcessMemory();

  // Create the OS kernel with the process
  kernel_.createProcess(*process_.get());

  return;
}

std::shared_ptr<simeng::MemoryInterface>
CoreInstance::createL1InstructionMemory(const simeng::MemInterfaceType type) {
  // Currently, only a flat memory interface can be used for the instruction
  // memory
  if (type != simeng::MemInterfaceType::Flat) {
    std::cerr << "Incompatible instruction memory interface type requested"
              << std::endl;
    exit(1);
  }

  // Create a L1I cache instance based on type supplied
  if (type == simeng::MemInterfaceType::Flat) {
    instructionMemory_ = std::make_shared<simeng::FlatMemoryInterface>(
        processMemory_, processMemorySize_);
  } else if (type == simeng::MemInterfaceType::Fixed) {
    instructionMemory_ = std::make_shared<simeng::FixedLatencyMemoryInterface>(
        processMemory_, processMemorySize_,
        config_["L1-Cache"]["Access-Latency"].as<uint16_t>());
  }

  return instructionMemory_;
}

void CoreInstance::setL1InstructionMemory(
    std::shared_ptr<simeng::MemoryInterface> memRef) {
  // Set the L1I cache instance to use
  instructionMemory_ = memRef;
  return;
}

std::shared_ptr<simeng::MemoryInterface> CoreInstance::createL1DataMemory(
    const simeng::MemInterfaceType type) {
  // Currently, if the core in use is emulation or in-order, only a flat data
  // memory interface can be used
  if (mode_ == SimulationMode::Emulation ||
      mode_ == SimulationMode::InOrderPipelined) {
    if (type != simeng::MemInterfaceType::Flat) {
      std::cerr << "Incompatible instruction memory interface type requested"
                << std::endl;
      exit(1);
    }
  }

  // Create a L1D cache instance based on type supplied
  if (type == simeng::MemInterfaceType::Flat) {
    dataMemory_ = std::make_shared<simeng::FlatMemoryInterface>(
        processMemory_, processMemorySize_);
  } else if (type == simeng::MemInterfaceType::Fixed) {
    dataMemory_ = std::make_shared<simeng::FixedLatencyMemoryInterface>(
        processMemory_, processMemorySize_,
        config_["L1-Cache"]["Access-Latency"].as<uint16_t>());
  }

  return dataMemory_;
}

void CoreInstance::setL1DataMemory(
    std::shared_ptr<simeng::MemoryInterface> memRef) {
  // Set the L1D cache instance to use
  dataMemory_ = memRef;
  return;
}

std::shared_ptr<simeng::Core> CoreInstance::createCore() {
  // Ensure all appropriate creation functions have been called
  if (instructionMemory_ == nullptr) {
    std::cerr << "Instruction memory not instantiated or set" << std::endl;
    exit(1);
  } else if (dataMemory_ == nullptr) {
    std::cerr << "Data memory not instantiated or set" << std::endl;
    exit(1);
  } else if (process_ == nullptr) {
    std::cerr << "Process not instantiated or set" << std::endl;
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
        // Resize vector to match number of execution ports available across all
        // reservation stations
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

  return core_;
}

void CoreInstance::createSpecialFileDirectory() {
  simeng::SpecialFileDirGen SFdir = simeng::SpecialFileDirGen(config_);
  // Create the Special Files directory if indicated to do so in Config
  if (config_["CPU-Info"]["Generate-Special-Dir"].as<std::string>() == "T") {
    // Remove any current special files dir
    SFdir.RemoveExistingSFDir();
    // Create new special files dir
    SFdir.GenerateSFDir();
  }

  return;
}

const SimulationMode CoreInstance::getSimulationMode() const { return mode_; }

}  // namespace simeng
