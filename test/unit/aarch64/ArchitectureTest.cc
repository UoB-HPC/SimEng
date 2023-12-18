#include <iostream>

#include "../ConfigInit.hh"
#include "gtest/gtest.h"
#include "simeng/CoreInstance.hh"
#include "simeng/RegisterFileSet.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/span.hh"
#include "simeng/version.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

// AArch64 Tests
class AArch64ArchitectureTest : public testing::Test {
 public:
  AArch64ArchitectureTest()
      : kernel(config::SimInfo::getConfig()["CPU-Info"]["Special-File-Dir-Path"]
                   .as<std::string>()) {
    arch = std::make_unique<Architecture>(kernel);
    kernel.createProcess(process);
  }

 protected:
  ConfigInit configInit = ConfigInit(config::ISA::AArch64);

  // fdivr z1.s, p0/m, z1.s, z0.s
  std::array<uint8_t, 4> validInstrBytes = {0x01, 0x80, 0x8c, 0x65};
  std::array<uint8_t, 4> invalidInstrBytes = {0x20, 0x00, 0x02, 0x8c};

  std::unique_ptr<Architecture> arch;
  kernel::Linux kernel;
  kernel::LinuxProcess process = kernel::LinuxProcess(
      span((char*)validInstrBytes.data(), validInstrBytes.size()));
};

TEST_F(AArch64ArchitectureTest, predecode) {
  // Test that mis-aligned instruction address results in error
  MacroOp output;
  uint8_t result = arch->predecode(validInstrBytes.data(),
                                   validInstrBytes.size(), 0x7, output);
  EXPECT_EQ(result, 1);
  EXPECT_EQ(output[0]->getInstructionAddress(), 0x7);
  EXPECT_EQ(output[0]->exceptionEncountered(), true);

  // Test that an invalid instruction returns instruction with an exception
  output = MacroOp();
  result = arch->predecode(invalidInstrBytes.data(), invalidInstrBytes.size(),
                           0x8, output);
  EXPECT_EQ(result, 4);
  EXPECT_EQ(output[0]->getInstructionAddress(), 0x8);
  EXPECT_EQ(output[0]->exceptionEncountered(), true);

  // Test that an instruction can be properly decoded
  output = MacroOp();
  result = arch->predecode(validInstrBytes.data(), validInstrBytes.size(), 0x4,
                           output);
  EXPECT_EQ(result, 4);
  EXPECT_EQ(output[0]->getInstructionAddress(), 0x4);
  EXPECT_EQ(output[0]->exceptionEncountered(), false);
}

TEST_F(AArch64ArchitectureTest, getSystemRegisterTag) {
  // Test incorrect system register will fail
  int32_t output = arch->getSystemRegisterTag(-1);
  EXPECT_EQ(output, -1);

  // Test for correct behaviour
  output = arch->getSystemRegisterTag(ARM64_SYSREG_DCZID_EL0);
  EXPECT_EQ(output, 0);
}

TEST_F(AArch64ArchitectureTest, handleException) {
  // Get Instruction
  MacroOp insn;
  uint8_t bytes = arch->predecode(invalidInstrBytes.data(),
                                  invalidInstrBytes.size(), 0x4, insn);
  EXPECT_EQ(bytes, 4);
  EXPECT_EQ(insn[0]->getInstructionAddress(), 0x4);
  EXPECT_EQ(insn[0]->exceptionEncountered(), true);

  // Get Core
  std::string executablePath = "";
  std::vector<std::string> executableArgs = {};
  std::unique_ptr<CoreInstance> coreInstance =
      std::make_unique<CoreInstance>(executablePath, executableArgs);
  const Core& core = *coreInstance->getCore();
  MemoryInterface& memInt = *coreInstance->getDataMemory();
  auto exceptionHandler = arch->handleException(insn[0], core, memInt);

  bool tickRes = exceptionHandler->tick();
  auto result = exceptionHandler->getResult();
  EXPECT_TRUE(tickRes);
  EXPECT_TRUE(result.fatal);
  // Instruction address for fatal exception is always 0.
  EXPECT_EQ(result.instructionAddress, 0x0);
}

TEST_F(AArch64ArchitectureTest, getInitialState) {
  std::vector<Register> regs = {
      {RegisterType::GENERAL, 31},
      {RegisterType::SYSTEM,
       (uint16_t)arch->getSystemRegisterTag(ARM64_SYSREG_DCZID_EL0)}};
  std::vector<RegisterValue> regVals = {{kernel.getInitialStackPointer(), 8},
                                        {20, 8}};

  arch::ProcessStateChange changes = arch->getInitialState();
  EXPECT_EQ(changes.type, arch::ChangeType::REPLACEMENT);
  EXPECT_EQ(changes.modifiedRegisters, regs);
  EXPECT_EQ(changes.modifiedRegisterValues, regVals);
}

TEST_F(AArch64ArchitectureTest, getMaxInstructionSize) {
  EXPECT_EQ(arch->getMaxInstructionSize(), 4);
}

TEST_F(AArch64ArchitectureTest, getVectorLength) {
  EXPECT_EQ(arch->getVectorLength(), 512);
}

TEST_F(AArch64ArchitectureTest, getStreamingVectorLength) {
  // Default SVL value is 128
  EXPECT_EQ(arch->getStreamingVectorLength(), 128);
}

TEST_F(AArch64ArchitectureTest, updateSystemTimerRegisters) {
  RegisterFileSet regFile = config::SimInfo::getArchRegStruct();

  uint8_t vctCount = 0;
  // In A64FX, Timer frequency = (2.5 * 1e9) / (100 * 1e6) = 18
  uint64_t vctModulo =
      (config::SimInfo::getConfig()["Core"]["Clock-Frequency-GHz"].as<float>() *
       1e9) /
      (config::SimInfo::getConfig()["Core"]["Timer-Frequency-MHz"]
           .as<uint32_t>() *
       1e6);
  for (int i = 0; i < 30; i++) {
    vctCount += (i % vctModulo) == 0 ? 1 : 0;
    arch->updateSystemTimerRegisters(&regFile, i);
    EXPECT_EQ(
        regFile
            .get({RegisterType::SYSTEM, (uint16_t)arch->getSystemRegisterTag(
                                            ARM64_SYSREG_PMCCNTR_EL0)})
            .get<uint64_t>(),
        i);
    EXPECT_EQ(
        regFile
            .get({RegisterType::SYSTEM, (uint16_t)arch->getSystemRegisterTag(
                                            ARM64_SYSREG_CNTVCT_EL0)})
            .get<uint64_t>(),
        vctCount);
  }
}

TEST_F(AArch64ArchitectureTest, getExecutionInfo) {
  MacroOp insn;
  uint64_t bytes = arch->predecode(validInstrBytes.data(),
                                   validInstrBytes.size(), 0x4, insn);
  EXPECT_EQ(bytes, 4);
  EXPECT_EQ(insn[0]->getInstructionAddress(), 0x4);
  EXPECT_EQ(insn[0]->exceptionEncountered(), false);

  // Insn[0] = fdivr z1.s, p0/m, z1.s, z0.s
  Instruction* aarch64Insn = reinterpret_cast<Instruction*>(insn[0].get());

  ExecutionInfo info = arch->getExecutionInfo(*aarch64Insn);

  // Latencies and Port numbers from a64fx.yaml
  EXPECT_EQ(info.latency, 98);
  EXPECT_EQ(info.stallCycles, 98);
  std::vector<uint16_t> ports = {0};
  EXPECT_EQ(info.ports, ports);
}

TEST_F(AArch64ArchitectureTest, get_set_SVCRVal) {
  EXPECT_EQ(arch->getSVCRval(), 0);
  arch->setSVCRval(3);
  EXPECT_EQ(arch->getSVCRval(), 3);
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
