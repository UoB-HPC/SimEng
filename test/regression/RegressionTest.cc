#include "RegressionTest.hh"

#include <string>

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
#include "simeng/BTBPredictor.hh"
#include "simeng/FixedLatencyMemoryInterface.hh"
#include "simeng/FlatMemoryInterface.hh"
#include "simeng/kernel/Linux.hh"
#include "simeng/kernel/LinuxProcess.hh"
#include "simeng/models/emulation/Core.hh"
#include "simeng/models/inorder/Core.hh"
#include "simeng/models/outoforder/Core.hh"

RegressionTest::~RegressionTest() {
  delete[] code_;
  delete[] processMemory_;
}

void RegressionTest::TearDown() {
  if (!programFinished_) {
    std::cout << testing::internal::GetCapturedStdout();
  }
}

YAML::Node RegressionTest::generateConfig() {
  YAML::Node config = YAML::Load(
      "{Core: {"
      "Simulation-Mode: outoforder, Clock-Frequency: 2.5,"
      "Fetch-Block-Alignment-Bits: 5"
      "}, Register-Set: {"
      "GeneralPurpose-Count: 154, FloatingPoint/SVE-Count: 90,"
      "Predicate-Count: 48, Conditional-Count: 128"
      "}, Pipeline-Widths: {"
      "Commit: 4, Dispatch-Rate: 4, FrontEnd: 4,"
      "LSQ-Completion: 2"
      "}, Queue-Sizes: {"
      "ROB: 180, Load: 64, Store: 36"
      "}, L1-Cache: {"
      "GeneralPurpose-Latency: 4, FloatingPoint-Latency: 4,"
      "SVE-Latency: 11, Bandwidth: 32,"
      "Permitted-Requests-Per-Cycle: 2,"
      "Permitted-Loads-Per-Cycle: 2,"
      "Permitted-Stores-Per-Cycle: 1"
      "}, Execution-Units: ["
      "{Pipelined: True, Blocking-Group: 0},"
      "{Pipelined: True, Blocking-Group: 0},"
      "{Pipelined: True, Blocking-Group: 0},"
      "{Pipelined: True, Blocking-Group: 0},"
      "{Pipelined: True, Blocking-Group: 0},"
      "{Pipelined: True, Blocking-Group: 0}"
      "]}");
  return config;
}

void RegressionTest::run(const char* source, const char* triple) {
  testing::internal::CaptureStdout();

  // Assemble the source to a flat binary
  assemble(source, triple);
  if (HasFatalFailure()) return;

  // Create a linux process from the assembled code block
  process_ = std::make_unique<simeng::kernel::LinuxProcess>(
      simeng::span<char>(reinterpret_cast<char*>(code_), codeSize_));
  ASSERT_TRUE(process_->isValid());
  uint64_t entryPoint = process_->getEntryPoint();

  // Allocate memory for the process and copy the full process image to it
  simeng::span<char> processImage = process_->getProcessImage();
  processMemorySize_ = processImage.size();
  processMemory_ = new char[processMemorySize_];
  std::copy(processImage.begin(), processImage.end(), processMemory_);

  // Create memory interfaces for instruction and data access
  simeng::FlatMemoryInterface instructionMemory(processMemory_,
                                                processMemorySize_);
  std::unique_ptr<simeng::FlatMemoryInterface> flatDataMemory =
      std::make_unique<simeng::FlatMemoryInterface>(processMemory_,
                                                    processMemorySize_);
  std::unique_ptr<simeng::FixedLatencyMemoryInterface> fixedLatencyDataMemory =
      std::make_unique<simeng::FixedLatencyMemoryInterface>(
          processMemory_, processMemorySize_, 4);
  std::unique_ptr<simeng::MemoryInterface> dataMemory;

  // Create the OS kernel and the process
  simeng::kernel::Linux kernel;
  kernel.createProcess(*process_);

  // Populate the heap with initial data (specified by the test being run).
  ASSERT_LT(process_->getHeapStart() + initialHeapData_.size(),
            process_->getStackPointer());
  std::copy(initialHeapData_.begin(), initialHeapData_.end(),
            processMemory_ + process_->getHeapStart());

  // Create the architecture
  architecture_ = createArchitecture(kernel);

  // Create a port allocator for an out-of-order core
  std::unique_ptr<simeng::pipeline::PortAllocator> portAllocator =
      createPortAllocator();

  // Create the reservationStation-Port mapping relationship
  const std::vector<std::pair<uint8_t, uint64_t>> rsArrangement = {
      {0, 60}, {0, 60}, {0, 60}, {0, 60}, {0, 60}, {0, 60}};

  // Create a branch predictor for a pipelined core
  simeng::BTBPredictor predictor(8);

  // Get pre-defined config file for OoO model
  YAML::Node config = generateConfig();

  // Create the core model
  switch (GetParam()) {
    case EMULATION:
      core_ = std::make_unique<simeng::models::emulation::Core>(
          instructionMemory, *flatDataMemory, entryPoint, processMemorySize_,
          *architecture_);
      dataMemory = std::move(flatDataMemory);
      break;
    case INORDER:
      core_ = std::make_unique<simeng::models::inorder::Core>(
          instructionMemory, *flatDataMemory, processMemorySize_, entryPoint,
          *architecture_, predictor);
      dataMemory = std::move(flatDataMemory);
      break;
    case OUTOFORDER:
      core_ = std::make_unique<simeng::models::outoforder::Core>(
          instructionMemory, *fixedLatencyDataMemory, processMemorySize_,
          entryPoint, *architecture_, predictor, *portAllocator, rsArrangement,
          config);
      dataMemory = std::move(fixedLatencyDataMemory);
      break;
  }

  // Run the core model until the program is complete
  while (!core_->hasHalted() || dataMemory->hasPendingRequests()) {
    ASSERT_LT(numTicks_, maxTicks_) << "Maximum tick count exceeded.";
    core_->tick();
    instructionMemory.tick();
    dataMemory->tick();
    numTicks_++;
  }

  stdout_ = testing::internal::GetCapturedStdout();
  std::cout << stdout_;

  programFinished_ = true;
}

void RegressionTest::assemble(const char* source, const char* triple) {
  // Initialise LLVM
  LLVMInitializeAArch64TargetInfo();
  LLVMInitializeAArch64TargetMC();
  LLVMInitializeAArch64AsmParser();

  // Get LLVM target
  std::string errStr;
  const llvm::Target* target =
      llvm::TargetRegistry::lookupTarget(triple, errStr);
  ASSERT_NE(target, nullptr) << errStr;

  // Create source buffer from assembly
  llvm::SourceMgr srcMgr;
  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> srcBuffer =
      llvm::MemoryBuffer::getMemBuffer(source);
  ASSERT_TRUE(srcBuffer) << "Failed to create LLVM source buffer";
  srcMgr.AddNewSourceBuffer(std::move(*srcBuffer), llvm::SMLoc());

  // Create MC register info
  std::unique_ptr<llvm::MCRegisterInfo> regInfo(
      target->createMCRegInfo(triple));
  ASSERT_NE(regInfo, nullptr) << "Failed to create LLVM register info";

  // Create MC asm info
  std::unique_ptr<llvm::MCAsmInfo> asmInfo(
      target->createMCAsmInfo(*regInfo, triple));
  ASSERT_NE(asmInfo, nullptr) << "Failed to create LLVM asm info";

  // Create MC context and object file info
  llvm::MCObjectFileInfo objectFileInfo;
  llvm::MCContext context(asmInfo.get(), regInfo.get(), &objectFileInfo,
                          &srcMgr);
  objectFileInfo.InitMCObjectFileInfo(llvm::Triple(triple), false, context,
                                      false);

  // Create MC subtarget info
  std::unique_ptr<llvm::MCSubtargetInfo> subtargetInfo(
      target->createMCSubtargetInfo(triple, "", "+sve"));
  ASSERT_NE(subtargetInfo, nullptr) << "Failed to create LLVM subtarget info";

  // Create MC instruction info
  std::unique_ptr<llvm::MCInstrInfo> instrInfo(target->createMCInstrInfo());
  ASSERT_NE(instrInfo, nullptr) << "Failed to create LLVM instruction info";

  // Create MC asm backend
  llvm::MCTargetOptions options;
  std::unique_ptr<llvm::MCAsmBackend> asmBackend(
      target->createMCAsmBackend(*subtargetInfo, *regInfo, options));
  ASSERT_NE(asmBackend, nullptr) << "Failed to create LLVM asm backend";

  // Create MC code emitter
  std::unique_ptr<llvm::MCCodeEmitter> codeEmitter(
      target->createMCCodeEmitter(*instrInfo, *regInfo, context));
  ASSERT_NE(codeEmitter, nullptr) << "Failed to create LLVM code emitter";

  // Create MC object writer
  llvm::SmallVector<char, 1024> objectStreamData;
  llvm::raw_svector_ostream objectStream(objectStreamData);
  std::unique_ptr<llvm::MCObjectWriter> objectWriter =
      asmBackend->createObjectWriter(objectStream);
  ASSERT_NE(objectWriter, nullptr) << "Failed to create LLVM object writer";

  // Create MC object streamer
  std::unique_ptr<llvm::MCStreamer> objectStreamer(
      target->createMCObjectStreamer(
          llvm::Triple(triple), context, std::move(asmBackend),
          std::move(objectWriter), std::move(codeEmitter), *subtargetInfo,
          options.MCRelaxAll, options.MCIncrementalLinkerCompatible, false));
  ASSERT_NE(objectStreamer, nullptr) << "Failed to create LLVM object streamer";

  // Create MC asm parser
  std::unique_ptr<llvm::MCAsmParser> asmParser(
      llvm::createMCAsmParser(srcMgr, context, *objectStreamer, *asmInfo));
  ASSERT_NE(asmParser, nullptr) << "Failed to create LLVM asm parser";

  // Create MC target asm parser
  std::unique_ptr<llvm::MCTargetAsmParser> targetAsmParser(
      target->createMCAsmParser(*subtargetInfo, *asmParser, *instrInfo,
                                options));
  ASSERT_NE(asmParser, nullptr) << "Failed to create LLVM target asm parser";
  asmParser->setTargetParser(*targetAsmParser);

  // Run asm parser to generate assembled object code
  ASSERT_FALSE(asmParser->Run(false));

  // Create ELF object from output
  llvm::StringRef objectData = objectStream.str();
  auto elfOrErr = llvm::object::ELFFile<
      llvm::object::ELFType<llvm::support::little, true>>::create(objectData);
  ASSERT_FALSE(elfOrErr.takeError()) << "Failed to load ELF object";
  auto& elf = *elfOrErr;

  // Get handle to .text section
  auto textOrErr = elf.getSection(".text");
  ASSERT_FALSE(textOrErr.takeError()) << "Failed to find .text section";
  auto& text = *textOrErr;

  // Get reference to .text section data
  auto textDataOrErr = elf.getSectionContents(text);
  ASSERT_FALSE(textDataOrErr.takeError()) << "Failed to get .text contents";
  llvm::ArrayRef<uint8_t> textData = *textDataOrErr;

  // Make copy of .text section data
  codeSize_ = textData.size();
  code_ = new uint8_t[codeSize_];
  std::copy(textData.begin(), textData.end(), code_);
}
