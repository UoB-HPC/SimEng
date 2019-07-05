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

#include "BTBPredictor.hh"
#include "FlatMemoryInterface.hh"
#include "kernel/Linux.hh"
#include "kernel/LinuxProcess.hh"
#include "models/emulation/Core.hh"
#include "models/inorder/Core.hh"
#include "models/outoforder/Core.hh"

RegressionTest::~RegressionTest() {
  delete[] code_;
  delete[] processMemory_;
}

void RegressionTest::run(const char* source, const char* triple) {
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
  simeng::FlatMemoryInterface dataMemory(processMemory_, processMemorySize_);

  // Create the OS kernel and the process
  simeng::kernel::Linux kernel;
  kernel.createProcess(*process_);

  // Create the architecture
  std::unique_ptr<simeng::arch::Architecture> arch = createArchitecture(kernel);

  // Create a port allocator for an out-of-order core
  std::unique_ptr<simeng::pipeline::PortAllocator> portAllocator =
      createPortAllocator();

  // Create a branch predictor for a pipelined core
  simeng::BTBPredictor predictor(8);

  // Create the core model
  switch (GetParam()) {
    case EMULATION:
      core_ = std::make_unique<simeng::models::emulation::Core>(
          instructionMemory, dataMemory, entryPoint, processMemorySize_, *arch);
      break;
    case INORDER:
      core_ = std::make_unique<simeng::models::inorder::Core>(
          instructionMemory, dataMemory, processMemorySize_, entryPoint, *arch,
          predictor);
      break;
    case OUTOFORDER:
      core_ = std::make_unique<simeng::models::outoforder::Core>(
          instructionMemory, dataMemory, processMemorySize_, entryPoint, *arch,
          predictor, *portAllocator);
      break;
  }

  // Run the core model until the program is complete
  while (!core_->hasHalted()) {
    core_->tick();
  }
}

void RegressionTest::assemble(const char* source, const char* triple) {
  // Initialise LLVM
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();

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
      target->createMCSubtargetInfo(triple, "", ""));
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
