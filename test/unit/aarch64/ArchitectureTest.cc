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
  // Setting core model to complex OoO model to more verbosely test the
  // Architecture class.
  ConfigInit configInit = ConfigInit(config::ISA::AArch64, R"YAML({
    Core: {
      Simulation-Mode: outoforder,
      Vector-Length: 512,
      Streaming-Vector-Length: 128
    },
    LSQ-L1-Interface: {
      Load-Bandwidth: 64,
      Store-Bandwidth: 64
    },
    Ports: { 
      '0': {Portname: Port 0, Instruction-Group-Support: [FP, SVE]},
      '1': {Portname: Port 1, Instruction-Group-Support: [PREDICATE]},
      '2': {Portname: Port 2, Instruction-Group-Support: [INT_SIMPLE, INT_MUL, STORE_DATA]},
      '3': {Portname: Port 3, Instruction-Group-Support: [FP_SIMPLE, FP_MUL, SVE_SIMPLE, SVE_MUL]},
      '4': {Portname: Port 4, Instruction-Group-Support: [INT_SIMPLE, INT_DIV_OR_SQRT]},
      '5': {Portname: Port 5, Instruction-Group-Support: [LOAD, STORE_ADDRESS, INT_SIMPLE_ARTH_NOSHIFT, INT_SIMPLE_LOGICAL_NOSHIFT, INT_SIMPLE_CMP]},
      '6': {Portname: Port 6, Instruction-Group-Support: [LOAD, STORE_ADDRESS, INT_SIMPLE_ARTH_NOSHIFT, INT_SIMPLE_LOGICAL_NOSHIFT, INT_SIMPLE_CMP]},
      '7': {Portname: Port 7, Instruction-Group-Support: [BRANCH]}
    },
    Reservation-Stations: {
      '0': {Size: 20, Dispatch-Rate: 2, Ports: [Port 0, Port 1, Port 2]},
      '1': {Size: 20, Dispatch-Rate: 2, Ports: [Port 3, Port 4]},
      '2': {Size: 10, Dispatch-Rate: 1, Ports: [Port 5]},
      '3': {Size: 10, Dispatch-Rate: 1, Ports: [Port 6]},
      '4': {Size: 19, Dispatch-Rate: 1, Ports: [Port 7]},
    },
    Execution-Units: {
      '0': {Pipelined: True, Blocking-Groups: [INT_DIV_OR_SQRT, FP_DIV_OR_SQRT, SVE_DIV_OR_SQRT]},
      '1': {Pipelined: True, Blocking-Groups: [INT_DIV_OR_SQRT, FP_DIV_OR_SQRT, SVE_DIV_OR_SQRT]},
      '2': {Pipelined: True, Blocking-Groups: [INT_DIV_OR_SQRT, FP_DIV_OR_SQRT, SVE_DIV_OR_SQRT]},
      '3': {Pipelined: True, Blocking-Groups: [INT_DIV_OR_SQRT, FP_DIV_OR_SQRT, SVE_DIV_OR_SQRT]},
      '4': {Pipelined: True, Blocking-Groups: [INT_DIV_OR_SQRT, FP_DIV_OR_SQRT, SVE_DIV_OR_SQRT]},
      '5': {Pipelined: True, Blocking-Groups: [INT_DIV_OR_SQRT, FP_DIV_OR_SQRT, SVE_DIV_OR_SQRT]},
      '6': {Pipelined: True, Blocking-Groups: [INT_DIV_OR_SQRT, FP_DIV_OR_SQRT, SVE_DIV_OR_SQRT]},
      '7': {Pipelined: True, Blocking-Groups: [INT_DIV_OR_SQRT, FP_DIV_OR_SQRT, SVE_DIV_OR_SQRT]}
    },
    Latencies: {
      '0': {Instruction-Groups: [INT], Execution-Latency: 2, Execution-Throughput: 2},
      '1': {Instruction-Groups: [INT_SIMPLE_ARTH_NOSHIFT, INT_SIMPLE_LOGICAL_NOSHIFT, INT_SIMPLE_CVT], Execution-Latency: 1, Execution-Throughput: 1},
      '2': {Instruction-Groups: [INT_MUL], Execution-Latency: 5, Execution-Throughput: 1},
      '3': {Instruction-Groups: [INT_DIV_OR_SQRT], Execution-Latency: 41, Execution-Throughput: 41},
      '4': {Instruction-Groups: [SCALAR_SIMPLE, VECTOR_SIMPLE_LOGICAL, SVE_SIMPLE_LOGICAL, VECTOR_SIMPLE_CMP, SVE_SIMPLE_CMP], Execution-Latency: 4, Execution-Throughput: 1},
      '5': {Instruction-Groups: [FP_DIV_OR_SQRT], Execution-Latency: 29, Execution-Throughput: 29},
      '6': {Instruction-Groups: [VECTOR_SIMPLE, SVE_SIMPLE, SCALAR_SIMPLE_CVT, FP_MUL, SVE_MUL], Execution-Latency: 9, Execution-Throughput: 1},
      '7': {Instruction-Groups: [SVE_DIV_OR_SQRT], Execution-Latency: 98, Execution-Throughput: 98},
      '8': {Instruction-Groups: [PREDICATE], Execution-Latency: 3, Execution-Throughput: 1},
      '9': {Instruction-Groups: [LOAD_SCALAR, LOAD_VECTOR, STORE_ADDRESS_SCALAR, STORE_ADDRESS_VECTOR], Execution-Latency: 3, Execution-Throughput: 1},
      '10': {Instruction-Groups: [LOAD_SVE, STORE_ADDRESS_SVE], Execution-Latency: 6, Execution-Throughput: 1}
    }
  })YAML");

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
  Instruction* aarch64Insn = reinterpret_cast<Instruction*>(output[0].get());
  EXPECT_EQ(result, 1);
  EXPECT_EQ(aarch64Insn->getInstructionAddress(), 0x7);
  EXPECT_EQ(aarch64Insn->exceptionEncountered(), true);
  EXPECT_EQ(aarch64Insn->getException(), InstructionException::MisalignedPC);

  // Test that an invalid instruction returns instruction with an exception
  output = MacroOp();
  result = arch->predecode(invalidInstrBytes.data(), invalidInstrBytes.size(),
                           0x8, output);
  aarch64Insn = reinterpret_cast<Instruction*>(output[0].get());
  EXPECT_EQ(result, 4);
  EXPECT_EQ(aarch64Insn->getInstructionAddress(), 0x8);
  EXPECT_EQ(aarch64Insn->exceptionEncountered(), true);
  EXPECT_EQ(aarch64Insn->getException(),
            InstructionException::EncodingUnallocated);

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
  Instruction* aarch64Insn = reinterpret_cast<Instruction*>(insn[0].get());
  EXPECT_EQ(bytes, 4);
  EXPECT_EQ(aarch64Insn->getInstructionAddress(), 0x4);
  EXPECT_EQ(aarch64Insn->exceptionEncountered(), true);
  EXPECT_EQ(aarch64Insn->getException(),
            InstructionException::EncodingUnallocated);

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
  // Insn[0] = fdivr z1.s, p0/m, z1.s, z0.s
  Instruction* aarch64Insn = reinterpret_cast<Instruction*>(insn[0].get());
  EXPECT_EQ(bytes, 4);
  EXPECT_EQ(aarch64Insn->getInstructionAddress(), 0x4);
  EXPECT_EQ(aarch64Insn->exceptionEncountered(), false);

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
