#include "simeng/CoreInstance.hh"

namespace simeng {

CoreInstance::CoreInstance(
    std::string executablePath, std::vector<std::string> executableArgs,
    std::shared_ptr<kernel::SyscallHandler> syscallHandler,
    std::shared_ptr<simeng::memory::Mem> mem)
    : config_(Config::get()), syscallHandler_(syscallHandler), memory_(mem) {
  generateCoreModel(executablePath, executableArgs);
}

// IGNORING SST RELATED CODE FOR NOW
// CoreInstance::CoreInstance(char* assembledSource, size_t sourceSize,
//                            std::string configPath)) {
//   config_ = simeng::ModelConfig(configPath).getConfigFile();
//   source_ = assembledSource;
//   sourceSize_ = sourceSize;
//   assembledSource_ = true;
//   // Pass an DEFAULT_PATH for executablePath and empty vector of strings for
//   // executableArgs.
//   generateCoreModel("Default", std::vector<std::string>{});
// }

CoreInstance::~CoreInstance() {
  if (source_) {
    delete[] source_;
  }
}

void CoreInstance::generateCoreModel(std::string executablePath,
                                     std::vector<std::string> executableArgs) {
  setSimulationMode();
  // Get the process image and its size
  // processMemorySize_ = process_->getProcessImageSize();

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

void CoreInstance::createL1InstructionMemory(
    const simeng::MemInterfaceType type) {
  // Create a L1I cache instance based on type supplied
  if (type == simeng::MemInterfaceType::Flat) {
    instructionMemory_ = std::make_shared<simeng::FlatMemoryInterface>(memory_);
  } else if (type == simeng::MemInterfaceType::Fixed) {
    instructionMemory_ = std::make_shared<simeng::FixedLatencyMemoryInterface>(
        memory_, config_["LSQ-L1-Interface"]["Access-Latency"].as<uint16_t>());
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
    dataMemory_ = std::make_shared<simeng::FlatMemoryInterface>(memory_);
  } else if (type == simeng::MemInterfaceType::Fixed) {
    dataMemory_ = std::make_shared<simeng::FixedLatencyMemoryInterface>(
        memory_, config_["LSQ-L1-Interface"]["Access-Latency"].as<uint16_t>());
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
        std::make_unique<simeng::arch::riscv::Architecture>(syscallHandler_);
  } else if (config_["Core"]["ISA"].as<std::string>() == "AArch64") {
    arch_ =
        std::make_unique<simeng::arch::aarch64::Architecture>(syscallHandler_);
  }

  // Construct branch predictor object
  predictor_ = std::make_unique<simeng::GenericPredictor>();

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
  if (mode_ == SimulationMode::Emulation) {
    core_ = std::make_shared<simeng::models::emulation::Core>(
        *instructionMemory_, *dataMemory_, *arch_);
  } else if (mode_ == SimulationMode::InOrderPipelined) {
    core_ = std::make_shared<simeng::models::inorder::Core>(
        *instructionMemory_, *dataMemory_, *arch_, *predictor_);
  } else if (mode_ == SimulationMode::OutOfOrder) {
    core_ = std::make_shared<simeng::models::outoforder::Core>(
        *instructionMemory_, *dataMemory_, *arch_, *predictor_,
        *portAllocator_);
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

}  // namespace simeng
