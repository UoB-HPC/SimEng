#include "../MockCore.hh"
#include "../MockInstruction.hh"
#include "../MockMemoryInterface.hh"
#include "gmock/gmock.h"
#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/ModelConfig.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/ExceptionHandler.hh"
#include "simeng/arch/aarch64/Instruction.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::ReturnRef;

class AArch64ExceptionHandlerTest : public ::testing::Test {
 public:
  AArch64ExceptionHandlerTest()
      : config(simeng::ModelConfig(SIMENG_SOURCE_DIR "/configs/a64fx.yaml")
                   .getConfigFile()),
        kernel(config["CPU-Info"]["Special-File-Dir-Path"].as<std::string>()),
        arch(kernel, config),
        physRegFileSet(arch.getRegisterFileStructures()),
        archRegFileSet(physRegFileSet) {}

 protected:
  YAML::Node config;

  MockCore core;
  MockMemoryInterface memory;
  kernel::Linux kernel;
  Architecture arch;

  RegisterFileSet physRegFileSet;
  ArchitecturalRegisterFileSet archRegFileSet;

  // fdivr z1.s, p0/m, z1.s, z0.s --- Just need a valid instruction to hijack
  const std::array<uint8_t, 4> validInstrBytes = {0x01, 0x80, 0x8c, 0x65};

  /** Helper constants for AArch64 general-purpose registers. */
  static constexpr Register R0 = {RegisterType::GENERAL, 0};
  static constexpr Register R1 = {RegisterType::GENERAL, 1};
  static constexpr Register R2 = {RegisterType::GENERAL, 2};
  static constexpr Register R3 = {RegisterType::GENERAL, 3};
  static constexpr Register R4 = {RegisterType::GENERAL, 4};
  static constexpr Register R5 = {RegisterType::GENERAL, 5};
  static constexpr Register R8 = {RegisterType::GENERAL, 8};
};

// The following exceptions are tested in /test/regression/aarch64/Exception.cc
// - InstructionException::StreamingModeUpdate,
// - InstructionException::ZAregisterStatusUpdate,
// - InstructionException::SMZAUpdate
// All system calls are tested in /test/regression/aarch64/Syscall.cc

// Test that a syscall is processed sucessfully
TEST_F(AArch64ExceptionHandlerTest, testSyscall) {
  // Create "syscall" instruction
  uint64_t insnAddr = 0x4;
  MacroOp uops;
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  InstructionException exception = InstructionException::SupervisorCall;
  std::shared_ptr<Instruction> insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  insn->setInstructionAddress(insnAddr);

  // Setup register file for `uname` syscall (chosen as minimal functionality)
  archRegFileSet.set(R8, RegisterValue(160, 8));

  // Create ExceptionHandler
  ExceptionHandler handler(insn, core, memory, kernel);

  // Tick exceptionHandler
  ON_CALL(core, getArchitecturalRegisterFileSet())
      .WillByDefault(ReturnRef(archRegFileSet));
  EXPECT_CALL(core, getArchitecturalRegisterFileSet()).Times(1);
  bool retVal = handler.tick();
  ExceptionResult result = handler.getResult();

  EXPECT_TRUE(retVal);
  EXPECT_FALSE(result.fatal);
  EXPECT_EQ(result.instructionAddress, insnAddr + 4);
  EXPECT_EQ(result.stateChange.type, ChangeType::REPLACEMENT);
}

// Test that `readStringThen()` operates as expected
TEST_F(AArch64ExceptionHandlerTest, readStringThen) {
  // Create new mock instruction and ExceptionHandler
  std::shared_ptr<MockInstruction> uopPtr(new MockInstruction);
  ExceptionHandler handler(uopPtr, core, memory, kernel);

  // Initialise variables
  size_t retVal = 0;
  char* buffer;
  buffer = (char*)malloc(256);
  for (int i = 0; i < 256; i++) {
    buffer[i] = 'q';
  }
  uint64_t addr = 1024;
  int maxLen = kernel::Linux::LINUX_PATH_MAX;

  MemoryAccessTarget target1 = {addr, 1};
  MemoryReadResult res1 = {target1, RegisterValue(0xAB, 1), 1};
  span<MemoryReadResult> res1Span = span<MemoryReadResult>(&res1, 1);

  MemoryAccessTarget target2 = {addr + 1, 1};
  MemoryReadResult res2 = {target2, RegisterValue(static_cast<int>('\0'), 1),
                           1};
  span<MemoryReadResult> res2Span = span<MemoryReadResult>(&res2, 1);

  // On first call to readStringThen, expect return of false and retVal to still
  // be 0, and buffer to be filled with `q`
  MemoryAccessTarget tar = {addr, 1};
  EXPECT_CALL(memory, requestRead(tar, 0)).Times(1);
  bool outcome =
      handler.readStringThen(buffer, addr, maxLen, [&retVal](auto length) {
        retVal = length;
        return true;
      });
  EXPECT_FALSE(outcome);
  EXPECT_EQ(retVal, 0);
  for (int i = 0; i < 256; i++) {
    EXPECT_EQ(buffer[i], 'q');
  }

  // ResumeHandling (called on tick()) should now be set to `readStringThen()`
  // so call this for our second pass.
  ON_CALL(memory, getCompletedReads())
      .WillByDefault(Return(span<MemoryReadResult>()));
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  outcome = handler.tick();
  // No memory reads completed yet so again expect to return false and no change
  // to `retval` or buffer
  EXPECT_FALSE(outcome);
  EXPECT_EQ(retVal, 0);
  for (int i = 0; i < 256; i++) {
    EXPECT_EQ(buffer[i], 'q');
  }

  // Call tick() again, but mimic a memory read completing
  tar = {addr + 1, 1};
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(res1Span));
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(memory, requestRead(tar, 0)).Times(1);
  outcome = handler.tick();
  // Completed read but still not complete, so outcome should be false, retVal
  // unchanged, but some data in the buffer
  EXPECT_FALSE(outcome);
  EXPECT_EQ(retVal, 0);
  for (int i = 0; i < 256; i++) {
    if (i == 0) {
      EXPECT_EQ(buffer[i], (char)0xAB);
    } else {
      EXPECT_EQ(buffer[i], 'q');
    }
  }

  // Call tick() for a final time, getting the final read result
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(res2Span));
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  outcome = handler.tick();
  // End of string '\0' found so expect `then()` to have been called, the
  // outcome to be true, and the buffer again to have updated
  EXPECT_TRUE(outcome);
  EXPECT_EQ(retVal, 1);
  for (int i = 0; i < 256; i++) {
    if (i == 0) {
      EXPECT_EQ(buffer[i], (char)0xAB);
    } else if (i == 1) {
      EXPECT_EQ(buffer[i], '\0');
    } else {
      EXPECT_EQ(buffer[i], 'q');
    }
  }
}

// Test that in `readStringThen()` if max length is 0, then is called straight
// away
TEST_F(AArch64ExceptionHandlerTest, readStringThen_maxLen0) {
  // Create new mock instruction and ExceptionHandler
  std::shared_ptr<MockInstruction> uopPtr(new MockInstruction);
  ExceptionHandler handler(uopPtr, core, memory, kernel);
  size_t retVal = 100;
  char* buffer;
  buffer = (char*)malloc(256);
  for (int i = 0; i < 256; i++) {
    buffer[i] = 'q';
  }
  uint64_t addr = 1024;
  int maxLen = 0;

  bool outcome =
      handler.readStringThen(buffer, addr, maxLen, [&retVal](auto length) {
        retVal = length;
        return true;
      });
  EXPECT_TRUE(outcome);
  EXPECT_EQ(retVal, -1);
  for (int i = 0; i < 256; i++) {
    EXPECT_EQ(buffer[i], 'q');
  }
}

// Test that in `readStringThen()` if max length has been met, then() is called
// and no more string is fetched
TEST_F(AArch64ExceptionHandlerTest, readStringThen_maxLenReached) {
  // Create new mock instruction and ExceptionHandler
  std::shared_ptr<MockInstruction> uopPtr(new MockInstruction);
  ExceptionHandler handler(uopPtr, core, memory, kernel);

  // Initialise variables
  size_t retVal = 100;
  char* buffer;
  buffer = (char*)malloc(256);
  for (int i = 0; i < 256; i++) {
    buffer[i] = 'q';
  }
  uint64_t addr = 1024;
  int maxLen = 1;

  MemoryAccessTarget target1 = {addr, 1};
  MemoryReadResult res1 = {target1, RegisterValue(0xAB, 1), 1};
  span<MemoryReadResult> res1Span = span<MemoryReadResult>(&res1, 1);

  // On first call to readStringThen, expect return of false and retVal to still
  // be 0, and buffer to be filled with `q`
  MemoryAccessTarget tar = {addr, 1};
  EXPECT_CALL(memory, requestRead(tar, 0)).Times(1);
  bool outcome =
      handler.readStringThen(buffer, addr, maxLen, [&retVal](auto length) {
        retVal = length;
        return true;
      });
  EXPECT_FALSE(outcome);
  EXPECT_EQ(retVal, 100);
  for (int i = 0; i < 256; i++) {
    EXPECT_EQ(buffer[i], 'q');
  }

  // ResumeHandling (called on tick()) should now be set to `readStringThen()`
  // so call this for our second pass.
  ON_CALL(memory, getCompletedReads())
      .WillByDefault(Return(span<MemoryReadResult>()));
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  outcome = handler.tick();
  // No memory reads completed yet so again expect to return false and no change
  // to `retval` or buffer
  EXPECT_FALSE(outcome);
  EXPECT_EQ(retVal, 100);
  for (int i = 0; i < 256; i++) {
    EXPECT_EQ(buffer[i], 'q');
  }

  // Call tick() again, but mimic a memory read completing
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(res1Span));
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  outcome = handler.tick();
  // Completed read and maxLength reached. Expect then() to have been called,
  // the outcome to be true, and the buffer to have updated. RetVal should be
  // maxLength
  EXPECT_TRUE(outcome);
  EXPECT_EQ(retVal, 1);
  for (int i = 0; i < 256; i++) {
    if (i == 0) {
      EXPECT_EQ(buffer[i], (char)0xAB);
    } else {
      EXPECT_EQ(buffer[i], 'q');
    }
  }
}

// Test that `readBufferThen()` operates as expected
TEST_F(AArch64ExceptionHandlerTest, readBufferThen) {
  // Create new mock instruction and ExceptionHandler
  std::shared_ptr<MockInstruction> uopPtr(new MockInstruction);
  uopPtr->setSequenceId(5);
  ExceptionHandler handler(uopPtr, core, memory, kernel);

  // Initialise needed values for function
  uint64_t retVal = 0;
  uint64_t ptr = 0;
  uint64_t length = 192;

  // Initialise data to "read" from MockMemory
  std::vector<char> dataVec(length, 'q');
  std::vector<char> dataVec2(length, 'q');
  // Initialise the two required targets (128-bytes per read request in
  // readBufferThen())
  MemoryAccessTarget tar1 = {ptr, 128};
  MemoryAccessTarget tar2 = {ptr + 128, static_cast<uint16_t>(length - 128)};
  // Initialise "responses" from the MockMemory
  MemoryReadResult res1 = {tar1, RegisterValue(dataVec.data() + ptr, 128),
                           uopPtr->getSequenceId()};
  MemoryReadResult res2 = {
      tar2, RegisterValue(dataVec.data() + ptr + 128, length - 128),
      uopPtr->getSequenceId()};

  // Confirm that internal dataBuffer is empty
  EXPECT_EQ(handler.dataBuffer.size(), 0);

  // Initial call to readBufferThen - expect resumeHandling to be updated to
  // readBufferThen and a memory read request to have occurred
  EXPECT_CALL(memory, requestRead(tar1, uopPtr->getSequenceId())).Times(1);
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  bool outcome = handler.readBufferThen(ptr, length, [&retVal]() {
    retVal = 10;
    return true;
  });
  EXPECT_FALSE(outcome);
  EXPECT_EQ(retVal, 0);
  EXPECT_EQ(handler.dataBuffer.size(), 0);

  // Can now call tick() - on call, emulate no reads completed
  ON_CALL(memory, getCompletedReads())
      .WillByDefault(Return(span<MemoryReadResult>()));
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  outcome = handler.tick();
  EXPECT_FALSE(outcome);
  EXPECT_EQ(retVal, 0);
  EXPECT_EQ(handler.dataBuffer.size(), 0);

  // Call tick() again, simulating completed read + new read requested as still
  // data to fetch
  ON_CALL(memory, getCompletedReads())
      .WillByDefault(Return(span<MemoryReadResult>(&res1, 1)));
  // Make sure clearCompletedReads() alters functionality of getCompletedReads()
  ON_CALL(memory, clearCompletedReads())
      .WillByDefault(::testing::InvokeWithoutArgs([&]() {
        ON_CALL(memory, getCompletedReads())
            .WillByDefault(Return(span<MemoryReadResult>()));
      }));
  EXPECT_CALL(memory, getCompletedReads()).Times(2);
  EXPECT_CALL(memory, clearCompletedReads()).Times(1);
  EXPECT_CALL(memory, requestRead(tar2, uopPtr->getSequenceId())).Times(1);
  outcome = handler.tick();
  EXPECT_FALSE(outcome);
  EXPECT_EQ(retVal, 0);
  EXPECT_EQ(handler.dataBuffer.size(), 128);
  for (int i = 0; i < handler.dataBuffer.size(); i++) {
    EXPECT_EQ(handler.dataBuffer[i], 'q');
  }

  // One final call to tick() to get last bits of data from memory and call
  // then()
  ON_CALL(memory, getCompletedReads())
      .WillByDefault(Return(span<MemoryReadResult>(&res2, 1)));
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(memory, clearCompletedReads()).Times(1);
  outcome = handler.tick();
  EXPECT_TRUE(outcome);
  EXPECT_EQ(retVal, 10);
  EXPECT_EQ(handler.dataBuffer.size(), length);
  for (int i = 0; i < length; i++) {
    EXPECT_EQ(handler.dataBuffer[i], static_cast<unsigned char>('q'));
  }
}

// Test that `readBufferThen()` calls then if length is 0
TEST_F(AArch64ExceptionHandlerTest, readBufferThen_length0) {
  // Create new mock instruction and ExceptionHandler
  std::shared_ptr<MockInstruction> uopPtr(new MockInstruction);
  ExceptionHandler handler(uopPtr, core, memory, kernel);

  const size_t expectedVal = 10;
  uint64_t retVal = 0;
  uint64_t ptr = 0;
  uint64_t length = 0;

  bool outcome = handler.readBufferThen(ptr, length, [&retVal]() {
    retVal = 10;
    return true;
  });
  EXPECT_TRUE(outcome);
  EXPECT_EQ(retVal, expectedVal);
}

// Test that all AArch64 exception types print as expected
TEST_F(AArch64ExceptionHandlerTest, printException) {
  ON_CALL(core, getArchitecturalRegisterFileSet())
      .WillByDefault(ReturnRef(archRegFileSet));
  uint64_t insnAddr = 0x4;
  MacroOp uops;

  // Create instruction for EncodingUnallocated
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  InstructionException exception = InstructionException::EncodingUnallocated;
  std::shared_ptr<Instruction> insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_0(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  std::stringstream buffer;
  std::streambuf* sbuf = std::cout.rdbuf();  // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());           // Redirect cout to buffer
  handler_0.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(buffer.str(),
              HasSubstr("[SimEng:ExceptionHandler] Encountered illegal "
                        "instruction exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for ExecutionNotYetImplemented
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::ExecutionNotYetImplemented;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_1(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_1.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(buffer.str(),
              HasSubstr("[SimEng:ExceptionHandler] Encountered execution "
                        "not-yet-implemented exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for MisalignedPC
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::MisalignedPC;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_2(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_2.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(buffer.str(),
              HasSubstr("[SimEng:ExceptionHandler] Encountered misaligned "
                        "program counter exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for DataAbort
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::DataAbort;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_3(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_3.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(
      buffer.str(),
      HasSubstr("[SimEng:ExceptionHandler] Encountered data abort exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for SupervisorCall
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::SupervisorCall;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_4(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_4.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(
      buffer.str(),
      HasSubstr(
          "[SimEng:ExceptionHandler] Encountered supervisor call exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for HypervisorCall
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::HypervisorCall;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_5(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_5.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(
      buffer.str(),
      HasSubstr(
          "[SimEng:ExceptionHandler] Encountered hypervisor call exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for SecureMonitorCall
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::SecureMonitorCall;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_6(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_6.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(buffer.str(), HasSubstr("[SimEng:ExceptionHandler] Encountered "
                                      "secure monitor call exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for NoAvailablePort
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::NoAvailablePort;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_7(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_7.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(buffer.str(), HasSubstr("[SimEng:ExceptionHandler] Encountered "
                                      "unsupported execution port exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for UnmappedSysReg
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::UnmappedSysReg;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_8(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_8.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(buffer.str(), HasSubstr("[SimEng:ExceptionHandler] Encountered "
                                      "unmapped system register exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for StreamingModeUpdate
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::StreamingModeUpdate;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_9(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_9.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(buffer.str(), HasSubstr("[SimEng:ExceptionHandler] Encountered "
                                      "streaming mode update exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for ZAregisterStatusUpdate
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::ZAregisterStatusUpdate;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_10(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_10.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(buffer.str(), HasSubstr("[SimEng:ExceptionHandler] Encountered "
                                      "ZA register status update exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for SMZAUpdate
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::SMZAUpdate;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_11(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_11.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(buffer.str(),
              HasSubstr("[SimEng:ExceptionHandler] Encountered streaming mode "
                        "& ZA register status update exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for ZAdisabled
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::ZAdisabled;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_12(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_12.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(buffer.str(),
              HasSubstr("[SimEng:ExceptionHandler] Encountered ZA register "
                        "access attempt when disabled exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for SMdisabled
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::SMdisabled;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_13(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_13.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(buffer.str(),
              HasSubstr("[SimEng:ExceptionHandler] Encountered SME execution "
                        "attempt when streaming mode disabled exception"));
  buffer.clear();
  uops.clear();

  // Create instruction for default case
  arch.predecode(validInstrBytes.data(), validInstrBytes.size(), insnAddr,
                 uops);
  exception = InstructionException::None;
  insn = std::make_shared<Instruction>(
      arch, static_cast<Instruction*>(uops[0].get())->getMetadata(), exception);
  // Create ExceptionHandler
  ExceptionHandler handler_14(insn, core, memory, kernel);
  // Capture std::cout and tick exceptionHandler
  sbuf = std::cout.rdbuf();         // Save cout's buffer
  std::cout.rdbuf(buffer.rdbuf());  // Redirect cout to buffer
  handler_14.printException(*static_cast<Instruction*>(insn.get()));
  std::cout.rdbuf(sbuf);  // Restore cout
  EXPECT_THAT(buffer.str(),
              HasSubstr("[SimEng:ExceptionHandler] Encountered unknown (id: "
                        "0) exception"));
  buffer.clear();
  uops.clear();
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng