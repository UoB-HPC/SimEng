#include "RegressionTest.hh"

#include <string>

#include "simeng/FixedLatencyMemoryInterface.hh"
#include "simeng/FlatMemoryInterface.hh"
#include "simeng/GenericPredictor.hh"
#include "simeng/OS/Process.hh"
#include "simeng/OS/SimOS.hh"
#include "simeng/models/emulation/Core.hh"
#include "simeng/models/inorder/Core.hh"
#include "simeng/models/outoforder/Core.hh"

RegressionTest::~RegressionTest() { delete[] code_; }

void RegressionTest::TearDown() {
  if (!programFinished_) {
    std::cout << testing::internal::GetCapturedStdout();
  }
}

void RegressionTest::run(const char* source, const char* triple,
                         const char* extensions) {
  testing::internal::CaptureStdout();

  // Assemble the source to a flat binary
  assemble(source, triple, extensions);
  if (HasFatalFailure()) return;

  // Get pre-defined config file for OoO model
  YAML::Node config = generateConfig();
  Config::set(config);

  const size_t memorySize =
      Config::get()["Simulation-Memory"]["Size"].as<size_t>();

  // Initialise the simulation memory
  memory_ = std::make_shared<simeng::memory::SimpleMem>(memorySize);

  // Initialise a SimOS object.
  simeng::OS::SimOS OS = simeng::OS::SimOS(DEFAULT_STR, {}, memory_);

  // Create a Process from the assembled code block.
  // Memory allocation for process images also takes place
  // during Process creation. The Elf binary is parsed
  // and relevant sections are copied to the process image.
  // The process image is finalised by the createStack method
  // which creates and populates the initial process stack.
  uint64_t procTID = OS.createProcess(
      {simeng::span<char>(reinterpret_cast<char*>(code_), codeSize_)});
  process_ = OS.getProcess(procTID);
  ASSERT_TRUE(process_->isValid());
  processMemorySize_ = process_->context_.progByteLen;

  // Create the architecture
  architecture_ = createArchitecture(OS.getSyscallHandler());
  std::shared_ptr<simeng::memory::MMU> mmu =
      std::make_shared<simeng::memory::MMU>(memory_, OS.getVAddrTranslator(),
                                            procTID);

  // Create memory interfaces for instruction and data access.
  // A shared_ptr to the MMU is passed to each interface.
  simeng::FlatMemoryInterface instructionMemory(mmu);
  std::unique_ptr<simeng::FlatMemoryInterface> flatDataMemory =
      std::make_unique<simeng::FlatMemoryInterface>(mmu);
  std::unique_ptr<simeng::FixedLatencyMemoryInterface> fixedLatencyDataMemory =
      std::make_unique<simeng::FixedLatencyMemoryInterface>(mmu, 4);

  std::unique_ptr<simeng::MemoryInterface> dataMemory;

  // Populate the heap with initial data (specified by the test being run).
  ASSERT_LT(process_->getHeapStart() + initialHeapData_.size(),
            process_->getStackPointer());

  uint64_t addr = process_->translate(process_->getHeapStart());
  memory_->sendUntimedData(initialHeapData_, addr, initialHeapData_.size());

  // Create a port allocator for an out-of-order core
  std::unique_ptr<simeng::pipeline::PortAllocator> portAllocator =
      createPortAllocator();

  // Create a branch predictor for a pipelined core
  simeng::GenericPredictor predictor = simeng::GenericPredictor();
  // Create the core model
  switch (std::get<0>(GetParam())) {
    case EMULATION:
      core_ = std::make_unique<simeng::models::emulation::Core>(
          instructionMemory, *flatDataMemory, *architecture_);
      dataMemory = std::move(flatDataMemory);
      break;
    case INORDER:
      core_ = std::make_unique<simeng::models::inorder::Core>(
          instructionMemory, *flatDataMemory, *architecture_, predictor);
      dataMemory = std::move(flatDataMemory);
      break;
    case OUTOFORDER:
      core_ = std::make_unique<simeng::models::outoforder::Core>(
          instructionMemory, *fixedLatencyDataMemory, *architecture_, predictor,
          *portAllocator);
      dataMemory = std::move(fixedLatencyDataMemory);
      break;
  }

  // Schedule Process on core
  /** NOTE: Not using SimOS as core_ must be unique_ptr, but SimOS expects
   * shared_ptr. */
  core_->schedule(process_->context_);

  // Run the core model until the program is complete
  /** NOTE: As we cannot register the core with SimOS, and as such no scheduling
   * occurs, we do not need to tick SimOS nor check its halted status in the
   * Regression Test. */
  while (!(core_->getStatus() == simeng::CoreStatus::halted) ||
         dataMemory->hasPendingRequests()) {
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

void RegressionTest::assemble(const char* source, const char* triple,
                              const char* extensions) {
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
  llvm::MCTargetOptions options;
#if SIMENG_LLVM_VERSION < 10
  std::unique_ptr<llvm::MCAsmInfo> asmInfo(
      target->createMCAsmInfo(*regInfo, triple));
#else
  std::unique_ptr<llvm::MCAsmInfo> asmInfo(
      target->createMCAsmInfo(*regInfo, triple, options));
#endif
  ASSERT_NE(asmInfo, nullptr) << "Failed to create LLVM asm info";

  // Create MC context and object file info
  llvm::MCObjectFileInfo objectFileInfo;
#if SIMENG_LLVM_VERSION < 13
  llvm::MCContext context(asmInfo.get(), regInfo.get(), &objectFileInfo,
                          &srcMgr);
  objectFileInfo.InitMCObjectFileInfo(llvm::Triple(triple), false, context,
                                      false);
#endif

  // Create MC subtarget info
  std::unique_ptr<llvm::MCSubtargetInfo> subtargetInfo(
      target->createMCSubtargetInfo(triple, "", extensions));
  ASSERT_NE(subtargetInfo, nullptr) << "Failed to create LLVM subtarget info";

// For LLVM versions 13+, MC subtarget info is needed to create context and
// object file info
#if SIMENG_LLVM_VERSION > 12
  llvm::MCContext context(llvm::Triple(triple), asmInfo.get(), regInfo.get(),
                          subtargetInfo.get(), &srcMgr, &options, false, "");

  objectFileInfo.initMCObjectFileInfo(context, false, false);
  context.setObjectFileInfo(&objectFileInfo);
#endif

  // Create MC instruction info
  std::unique_ptr<llvm::MCInstrInfo> instrInfo(target->createMCInstrInfo());
  ASSERT_NE(instrInfo, nullptr) << "Failed to create LLVM instruction info";

  // Create MC asm backend
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
  auto textOrErr = elf.getSection(2);
  ASSERT_FALSE(textOrErr.takeError()) << "Failed to find .text section";
  auto& text = *textOrErr;

  // Get reference to .text section data
#if SIMENG_LLVM_VERSION < 12
  auto textDataOrErr = elf.getSectionContents(text);
#else
  auto textDataOrErr = elf.getSectionContents(*text);
#endif
  ASSERT_FALSE(textDataOrErr.takeError()) << "Failed to get .text contents";
  llvm::ArrayRef<uint8_t> textData = *textDataOrErr;

  // Make copy of .text section data
  codeSize_ = textData.size();
  if (code_) delete[] code_;
  code_ = new uint8_t[codeSize_];
  std::copy(textData.begin(), textData.end(), code_);
}
