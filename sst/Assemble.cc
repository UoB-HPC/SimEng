#include "Assemble.hh"

#ifdef SIMENG_ENABLE_SST_TESTS
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
#include "llvm/Support/TargetSelect.h"
#if SIMENG_LLVM_VERSION < 14
#include "llvm/Support/TargetRegistry.h"
#else
#include "llvm/MC/TargetRegistry.h"
#endif
#endif

using namespace SST::SSTSimEng;

#define ASSERT(expr, errStr)                                                 \
  if (!(expr)) {                                                             \
    std::cerr << "[SSTSimEngTest:Assembler] Error occured while assembling " \
                 "source through LLVM:\n"                                    \
              << errStr << std::endl;                                        \
    exit(1);                                                                 \
  }

Assembler::Assembler(std::string source) {
  std::string sourceWithTerminator = source + "\n.word 0";
  assemble(source.c_str(), "aarch64");
};

Assembler::~Assembler(){};

// The assemble method is conditionally compiled. The
// SIMENG_ENABLE_SST_TESTS compile definition adds LLVM as a
// dependency to the testing framework, so that a string of instructions can be
// assembled and executed by SSTSimEng. If SIMENG_ENABLE_SST_TESTS is not
// defined SST will not be testing mode and hence LLVM is not required as a
// dependency.
#ifdef SIMENG_ENABLE_SST_TESTS
void Assembler::assemble(const char* source, const char* triple) {
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
#if SIMENG_LLVM_VERSION < 13
  llvm::MCContext context(asmInfo.get(), regInfo.get(), &objectFileInfo,
                          &srcMgr);
  objectFileInfo.InitMCObjectFileInfo(llvm::Triple(triple), false, context,
                                      false);
#endif

  // Create MC subtarget info
  const char* subtargetFeatures;
#if SIMENG_LLVM_VERSION < 14
  subtargetFeatures = "+sve,+lse";
#else
  subtargetFeatures = "+sve,+lse,+sve2,+sme";
#endif
  std::unique_ptr<llvm::MCSubtargetInfo> subtargetInfo(
      target->createMCSubtargetInfo(triple, "", subtargetFeatures));
  ASSERT(subtargetInfo != nullptr, "Failed to create LLVM subtarget info");

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
#else
void Assembler::assemble(const char* source, const char* triple) {
  std::cerr
      << "[SSTSimEng:Assembler] assembled_with_source parameter was "
         "supplied as true by the SST configuration file used. However, LLVM "
         "wasn't injected as a dependency to properly assemble source "
         "instructions. Please ensure SIMENG_ENABLE_SST_TESTS compile option "
         "is specified during the initial cmake configuration step."
      << std::endl;
  std::exit(1);
}
#endif

char* Assembler::getAssembledSource() { return reinterpret_cast<char*>(code_); }
size_t Assembler::getAssembledSourceSize() { return codeSize_; }
