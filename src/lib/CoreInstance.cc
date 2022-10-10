#include "simeng/CoreInstance.hh"

#include <algorithm>

#ifdef SIMENG_ENABLE_TESTS
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/Object/ELF.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#endif

#define ASSERT(expr, errStr)                                      \
  if (!(expr)) {                                                  \
    std::cerr << "[SimEng:CoreInstance] " << errStr << std::endl; \
    exit(1);                                                      \
  }

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
#ifdef SIMENG_ENABLE_TESTS
CoreInstance::CoreInstance(std::string instructions, std::string configPath) {
  constructBinaryByLLVM_ = true;
  config_ = simeng::ModelConfig(configPath).getConfigFile();
  std::string sourceWithTerminator = instructions + "\n.word 0";
  assemble(sourceWithTerminator.c_str(), "aarch64");
  generateCoreModel("", std::vector<std::string>{});
};
#endif

#ifdef SIMENG_ENABLE_TESTS
void CoreInstance::assemble(const char* source, const char* triple) {
  ASSERT(std::string(triple) == "aarch64",
         "Architectures other than aarch64 not supported yet.");
  // Initialise LLVM
  LLVMInitializeAArch64TargetInfo();
  LLVMInitializeAArch64TargetMC();
  LLVMInitializeAArch64AsmParser();

  // Get LLVM target
  std::string errStr;
  const llvm::Target* target =
      llvm::TargetRegistry::lookupTarget(triple, errStr);
  ASSERT(target != nullptr, errStr);

  // Create source buffer from assembly
  llvm::SourceMgr srcMgr;
  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> srcBuffer =
      llvm::MemoryBuffer::getMemBuffer(source);
  ASSERT(srcBuffer, "Failed to create LLVM source buffer")
  srcMgr.AddNewSourceBuffer(std::move(*srcBuffer), llvm::SMLoc());

  // Create MC register info
  std::unique_ptr<llvm::MCRegisterInfo> regInfo(
      target->createMCRegInfo(triple));
  ASSERT(regInfo != nullptr, "Failed to create LLVM register info");

  // Create MC asm info
  llvm::MCTargetOptions options;
#if SIMENG_LLVM_VERSION < 10
  std::unique_ptr<llvm::MCAsmInfo> asmInfo(
      target->createMCAsmInfo(*regInfo, triple));
#else
  std::unique_ptr<llvm::MCAsmInfo> asmInfo(
      target->createMCAsmInfo(*regInfo, triple, options));
#endif
  ASSERT(asmInfo != nullptr, "Failed to create LLVM asm info");

  // Create MC context and object file info
  llvm::MCObjectFileInfo objectFileInfo;
  llvm::MCContext context(asmInfo.get(), regInfo.get(), &objectFileInfo,
                          &srcMgr);
  objectFileInfo.InitMCObjectFileInfo(llvm::Triple(triple), false, context,
                                      false);

  // Create MC subtarget info
  std::unique_ptr<llvm::MCSubtargetInfo> subtargetInfo(
      target->createMCSubtargetInfo(triple, "", "+sve,+lse"));
  ASSERT(subtargetInfo != nullptr, "Failed to create LLVM subtarget info");

  // Create MC instruction info
  std::unique_ptr<llvm::MCInstrInfo> instrInfo(target->createMCInstrInfo());
  ASSERT(instrInfo != nullptr, "Failed to create LLVM instruction info");

  // Create MC asm backend
  std::unique_ptr<llvm::MCAsmBackend> asmBackend(
      target->createMCAsmBackend(*subtargetInfo, *regInfo, options));
  ASSERT(asmBackend != nullptr, "Failed to create LLVM asm backend");

  // Create MC code emitter
  std::unique_ptr<llvm::MCCodeEmitter> codeEmitter(
      target->createMCCodeEmitter(*instrInfo, *regInfo, context));
  ASSERT(codeEmitter != nullptr, "Failed to create LLVM code emitter");

  // Create MC object writer
  llvm::SmallVector<char, 1024> objectStreamData;
  llvm::raw_svector_ostream objectStream(objectStreamData);
  std::unique_ptr<llvm::MCObjectWriter> objectWriter =
      asmBackend->createObjectWriter(objectStream);
  ASSERT(objectWriter != nullptr, "Failed to create LLVM object writer");

  // Create MC object streamer
  std::unique_ptr<llvm::MCStreamer> objectStreamer(
      target->createMCObjectStreamer(
          llvm::Triple(triple), context, std::move(asmBackend),
          std::move(objectWriter), std::move(codeEmitter), *subtargetInfo,
          options.MCRelaxAll, options.MCIncrementalLinkerCompatible, false));
  ASSERT(objectStreamer != nullptr, "Failed to create LLVM object streamer");

  // Create MC asm parser
  std::unique_ptr<llvm::MCAsmParser> asmParser(
      llvm::createMCAsmParser(srcMgr, context, *objectStreamer, *asmInfo));
  ASSERT(asmParser != nullptr, "Failed to create LLVM asm parser");

  // Create MC target asm parser
  std::unique_ptr<llvm::MCTargetAsmParser> targetAsmParser(
      target->createMCAsmParser(*subtargetInfo, *asmParser, *instrInfo,
                                options));
  ASSERT(asmParser != nullptr, "Failed to create LLVM target asm parser");
  asmParser->setTargetParser(*targetAsmParser);

  // Run asm parser to generate assembled object code
  ASSERT(!asmParser->Run(false), "");

  // Create ELF object from output
  llvm::StringRef objectData = objectStream.str();
  auto elfOrErr = llvm::object::ELFFile<
      llvm::object::ELFType<llvm::support::little, true>>::create(objectData);
  ASSERT(!elfOrErr.takeError(), "Failed to load ELF object");
  auto& elf = *elfOrErr;

  // Get handle to .text section
  auto textOrErr = elf.getSection(2);
  ASSERT(!textOrErr.takeError(), "Failed to find .text section");
  auto& text = *textOrErr;

  // Get reference to .text section data
#if SIMENG_LLVM_VERSION < 12
  auto textDataOrErr = elf.getSectionContents(text);
#else
  auto textDataOrErr = elf.getSectionContents(*text);
#endif
  ASSERT(!textDataOrErr.takeError(), "Failed to get .text contents");
  llvm::ArrayRef<uint8_t> textData = *textDataOrErr;

  // Make copy of .text section data
  codeSize_ = textData.size();
  code_ = new uint8_t[codeSize_];
  std::copy(textData.begin(), textData.end(), code_);
}
#endif

CoreInstance::~CoreInstance() {
#ifdef SIMENG_ENABLE_TESTS
  if (code_ != nullptr) delete[] code_;
#endif
}

void CoreInstance::generateCoreModel(std::string executablePath,
                                     std::vector<std::string> executableArgs) {
  setSimulationMode();
#ifdef SIMENG_ENABLE_TESTS
  // if instructions have been supplied as a string, were assembled by
  // LLVM then create the LinuxProcess with the assembled source.
  if (constructBinaryByLLVM_) {
    process_ = std::make_unique<simeng::kernel::LinuxProcess>(
        simeng::span<char>(reinterpret_cast<char*>(code_), codeSize_), config_);
    ASSERT(process_->isValid(),
           "[SimEng:CoreInstance] Could not create process based on "
           "supplied instructions.");
    createProcessMemory();
    kernel_.createProcess(*process_.get());
  } else {
    createProcess(executablePath, executableArgs);
  }
#else
  createProcess(executablePath, executableArgs);
#endif
  // Check to see if either of the instruction or data memory interfaces
  // should be created. Don't create the core if either interface is marked as
  // External as they must be set manually prior to the core's creation.

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
  // Get the simualtion mode as defined by the set configuration, defaulting
  // to emulation
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
  std::cout << "Creating core" << std::endl;
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

const std::string CoreInstance::getSimulationModeString() const {
  return modeString_;
}

std::shared_ptr<simeng::Core> CoreInstance::getCore() const {
  if (core_ == nullptr) {
    std::cerr
        << "[SimEng:CoreInstance] Core object not constructed. If either "
           "data "
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
    std::cerr << "`[SimEng:CoreInstance] External` instruction memory object "
                 "not set."
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

}  // namespace simeng
