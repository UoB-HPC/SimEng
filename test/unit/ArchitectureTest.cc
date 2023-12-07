#include "gtest/gtest.h"
#include "simeng/CoreInstance.hh"
#include "simeng/ModelConfig.hh"
#include "simeng/RegisterFileSet.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/span.hh"
#include "simeng/version.hh"

namespace simeng {

// AArch64 Tests
class AArch64ArchitectureTest : public testing::Test {
 public:
  AArch64ArchitectureTest() {
    arch =
        std::make_unique<simeng::arch::aarch64::Architecture>(kernel, config);
    kernel.createProcess(process);
  }

 protected:
  YAML::Node config =
      simeng::ModelConfig(SIMENG_SOURCE_DIR "/configs/a64fx.yaml")
          .getConfigFile();

  // fdivr z1.s, p0/m, z1.s, z0.s
  std::array<uint8_t, 4> validInstrBytes = {0x01, 0x80, 0x8c, 0x65};
  std::array<uint8_t, 4> invalidInstrBytes = {0x20, 0x00, 0x02, 0x8c};

  std::unique_ptr<simeng::arch::aarch64::Architecture> arch;
  simeng::kernel::Linux kernel;
  simeng::kernel::LinuxProcess process = simeng::kernel::LinuxProcess(
      simeng::span((char*)validInstrBytes.data(), validInstrBytes.size()),
      config);
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

TEST_F(AArch64ArchitectureTest, getRegisterFileStructures) {
  auto output = arch->getRegisterFileStructures();
  EXPECT_EQ(output[0].bytes, 8);
  EXPECT_EQ(output[0].quantity, 32);
  EXPECT_EQ(output[1].bytes, 256);
  EXPECT_EQ(output[1].quantity, 32);
  EXPECT_EQ(output[2].bytes, 32);
  EXPECT_EQ(output[2].quantity, 17);
  EXPECT_EQ(output[3].bytes, 1);
  EXPECT_EQ(output[3].quantity, 1);
  EXPECT_EQ(output[4].bytes, 8);
  EXPECT_EQ(output[4].quantity, arch->getNumSystemRegisters());
  EXPECT_EQ(output[5].bytes, 256);
  EXPECT_EQ(output[5].quantity, (128 / 8));  // default SVL value is 128
}

TEST_F(AArch64ArchitectureTest, getSystemRegisterTag) {
  // Test incorrect system register will fail
  int32_t output = arch->getSystemRegisterTag(-1);
  EXPECT_EQ(output, -1);

  // Test for correct behaviour
  output = arch->getSystemRegisterTag(ARM64_SYSREG_DCZID_EL0);
  EXPECT_EQ(output, 0);
}

TEST_F(AArch64ArchitectureTest, getNumSystemRegisters) {
  uint16_t output = arch->getNumSystemRegisters();
  EXPECT_EQ(output, 8);
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
  std::unique_ptr<simeng::CoreInstance> coreInstance =
      std::make_unique<simeng::CoreInstance>(executablePath, executableArgs);
  const simeng::Core& core = *coreInstance->getCore();
  simeng::MemoryInterface& memInt = *coreInstance->getDataMemory();
  auto exceptionHandler = arch->handleException(insn[0], core, memInt);

  bool tickRes = exceptionHandler->tick();
  auto result = exceptionHandler->getResult();
  EXPECT_TRUE(tickRes);
  EXPECT_TRUE(result.fatal);
  // Instruction address for fatal exception is always 0.
  EXPECT_EQ(result.instructionAddress, 0x0);
}

TEST_F(AArch64ArchitectureTest, getInitialState) {
  std::vector<simeng::Register> regs = {
      {simeng::arch::aarch64::RegisterType::GENERAL, 31},
      {simeng::arch::aarch64::RegisterType::SYSTEM,
       (uint16_t)arch->getSystemRegisterTag(ARM64_SYSREG_DCZID_EL0)}};
  std::vector<simeng::RegisterValue> regVals = {
      {kernel.getInitialStackPointer(), 8}, {20, 8}};

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
  RegisterFileSet regFile = arch->getRegisterFileStructures();

  uint8_t vctCount = 0;
  // In A64FX, Timer frequency = (2.5 * 1e9) / (100 * 1e6) = 18
  uint64_t vctModulo = (config["Core"]["Clock-Frequency"].as<float>() * 1e9) /
                       (config["Core"]["Timer-Frequency"].as<uint32_t>() * 1e6);
  for (int i = 0; i < 30; i++) {
    vctCount += (i % vctModulo) == 0 ? 1 : 0;
    arch->updateSystemTimerRegisters(&regFile, i);
    EXPECT_EQ(regFile
                  .get({simeng::arch::aarch64::RegisterType::SYSTEM,
                        (uint16_t)arch->getSystemRegisterTag(
                            ARM64_SYSREG_PMCCNTR_EL0)})
                  .get<uint64_t>(),
              i);
    EXPECT_EQ(regFile
                  .get({simeng::arch::aarch64::RegisterType::SYSTEM,
                        (uint16_t)arch->getSystemRegisterTag(
                            ARM64_SYSREG_CNTVCT_EL0)})
                  .get<uint64_t>(),
              vctCount);
  }
}

TEST_F(AArch64ArchitectureTest, getConfigPhysicalRegisterStructure) {
  std::vector<RegisterFileStructure> regStruct =
      arch->getConfigPhysicalRegisterStructure(config);
  // Values taken from a64fx.yaml config file
  EXPECT_EQ(regStruct[0].bytes, 8);
  EXPECT_EQ(regStruct[0].quantity, 96);
  EXPECT_EQ(regStruct[1].bytes, 256);
  EXPECT_EQ(regStruct[1].quantity, 128);
  EXPECT_EQ(regStruct[2].bytes, 32);
  EXPECT_EQ(regStruct[2].quantity, 48);
  EXPECT_EQ(regStruct[3].bytes, 1);
  EXPECT_EQ(regStruct[3].quantity, 128);
  EXPECT_EQ(regStruct[4].bytes, 8);
  EXPECT_EQ(regStruct[4].quantity, arch->getNumSystemRegisters());
  EXPECT_EQ(regStruct[5].bytes, 256);
  EXPECT_EQ(regStruct[5].quantity, 128 / 8);  // Default SVL is 128
}

TEST_F(AArch64ArchitectureTest, getConfigPhysicalRegisterQuantities) {
  std::vector<uint16_t> physQuants =
      arch->getConfigPhysicalRegisterQuantities(config);
  // Values taken from a64fx.yaml config file
  EXPECT_EQ(physQuants[0], 96);
  EXPECT_EQ(physQuants[1], 128);
  EXPECT_EQ(physQuants[2], 48);
  EXPECT_EQ(physQuants[3], 128);
  EXPECT_EQ(physQuants[4], arch->getNumSystemRegisters());
  EXPECT_EQ(physQuants[5], 128 / 8);  // Default SVL is 128
}

TEST_F(AArch64ArchitectureTest, getExecutionInfo) {
  MacroOp insn;
  uint64_t bytes = arch->predecode(validInstrBytes.data(),
                                   validInstrBytes.size(), 0x4, insn);
  EXPECT_EQ(bytes, 4);
  EXPECT_EQ(insn[0]->getInstructionAddress(), 0x4);
  EXPECT_EQ(insn[0]->exceptionEncountered(), false);

  // Insn[0] = fdivr z1.s, p0/m, z1.s, z0.s
  simeng::arch::aarch64::Instruction* aarch64Insn =
      (simeng::arch::aarch64::Instruction*)insn[0].get();
  // The above *dirty* conversion between Abstract and derived types is required
  // to avoid the use of a dynamic_cast.

  simeng::arch::aarch64::ExecutionInfo info =
      arch->getExecutionInfo(*aarch64Insn);

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

// RISC-V Tests
class RiscVArchitectureTest : public testing::Test {
 public:
  RiscVArchitectureTest() {
    arch = std::make_unique<simeng::arch::riscv::Architecture>(kernel, config);
    kernel.createProcess(process);
  }

 protected:
  YAML::Node config =
      simeng::ModelConfig(SIMENG_SOURCE_DIR "/configs/DEMO_RISCV.yaml")
          .getConfigFile();

  // addi	sp, ra, 2000
  std::array<uint8_t, 4> validInstrBytes = {0x13, 0x81, 0x00, 0x7d};
  std::array<uint8_t, 4> invalidInstrBytes = {0x7d, 0x00, 0x81, 0xbb};

  std::unique_ptr<simeng::arch::riscv::Architecture> arch;
  simeng::kernel::Linux kernel;
  simeng::kernel::LinuxProcess process = simeng::kernel::LinuxProcess(
      simeng::span((char*)validInstrBytes.data(), validInstrBytes.size()),
      config);
};

TEST_F(RiscVArchitectureTest, predecode) {
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

TEST_F(RiscVArchitectureTest, getRegisterFileStructures) {
  auto output = arch->getRegisterFileStructures();
  EXPECT_EQ(output[0].bytes, 8);
  EXPECT_EQ(output[0].quantity, 32);
  EXPECT_EQ(output[1].bytes, 8);
  EXPECT_EQ(output[1].quantity, 32);
  EXPECT_EQ(output[2].bytes, 8);
  EXPECT_EQ(output[2].quantity, arch->getNumSystemRegisters());
}

TEST_F(RiscVArchitectureTest, getSystemRegisterTag) {
  // Test incorrect system register will fail
  int32_t output = arch->getSystemRegisterTag(-1);
  EXPECT_EQ(output, -1);

  // Test for correct behaviour
  // TODO: Implement once system registers have been added
}

TEST_F(RiscVArchitectureTest, getNumSystemRegisters) {
  uint16_t output = arch->getNumSystemRegisters();
  EXPECT_EQ(output, 0);
}

TEST_F(RiscVArchitectureTest, handleException) {
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
  std::unique_ptr<simeng::CoreInstance> coreInstance =
      std::make_unique<simeng::CoreInstance>(executablePath, executableArgs);
  const simeng::Core& core = *coreInstance->getCore();
  simeng::MemoryInterface& memInt = *coreInstance->getDataMemory();
  auto exceptionHandler = arch->handleException(insn[0], core, memInt);

  bool tickRes = exceptionHandler->tick();
  auto result = exceptionHandler->getResult();
  EXPECT_TRUE(tickRes);
  EXPECT_TRUE(result.fatal);
  // Instruction address for fatal exception is always 0.
  EXPECT_EQ(result.instructionAddress, 0x0);
}

TEST_F(RiscVArchitectureTest, getInitialState) {
  std::vector<simeng::Register> regs = {
      {simeng::arch::riscv::RegisterType::GENERAL, 2}};
  std::vector<simeng::RegisterValue> regVals = {
      {kernel.getInitialStackPointer(), 8}};

  arch::ProcessStateChange changes = arch->getInitialState();
  EXPECT_EQ(changes.type, arch::ChangeType::REPLACEMENT);
  EXPECT_EQ(changes.modifiedRegisters, regs);
  EXPECT_EQ(changes.modifiedRegisterValues, regVals);
}

TEST_F(RiscVArchitectureTest, getMaxInstructionSize) {
  EXPECT_EQ(arch->getMaxInstructionSize(), 4);
}

TEST_F(RiscVArchitectureTest, updateSystemTimerRegisters) {
  // TODO: add tests once function has non-blank implementation.
}

TEST_F(RiscVArchitectureTest, getConfigPhysicalRegisterStructure) {
  std::vector<RegisterFileStructure> regStruct =
      arch->getConfigPhysicalRegisterStructure(config);
  // Values taken from DEMO_RISCV.yaml config file
  EXPECT_EQ(regStruct[0].bytes, 8);
  EXPECT_EQ(regStruct[0].quantity, 154);
  EXPECT_EQ(regStruct[1].bytes, 8);
  EXPECT_EQ(regStruct[1].quantity, 90);
  EXPECT_EQ(regStruct[2].bytes, 8);
  EXPECT_EQ(regStruct[2].quantity, arch->getNumSystemRegisters());
}

TEST_F(RiscVArchitectureTest, getConfigPhysicalRegisterQuantities) {
  std::vector<uint16_t> physQuants =
      arch->getConfigPhysicalRegisterQuantities(config);
  // Values taken from DEMO_RISCV.yaml config file
  EXPECT_EQ(physQuants[0], 154);
  EXPECT_EQ(physQuants[1], 90);
  EXPECT_EQ(physQuants[2], arch->getNumSystemRegisters());
}

}  // namespace simeng
