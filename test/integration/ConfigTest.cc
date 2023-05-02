#include <fstream>
#include <iostream>

#include "gtest/gtest.h"
#include "simeng/config/SimInfo.hh"

namespace {

// Test generated default values are correct
TEST(ConfigTest, Default) {
  // Test key default values exposed in SimInfo
  EXPECT_EQ(simeng::config::SimInfo::getConfigPath(), "Default");
  EXPECT_EQ(simeng::config::SimInfo::getISA(), simeng::config::ISA::AArch64);
  EXPECT_EQ(simeng::config::SimInfo::getSimMode(),
            simeng::config::simMode::emulation);
  EXPECT_EQ(simeng::config::SimInfo::getSimModeStr(), "Emulation");
  std::vector<arm64_sysreg> sysRegisterEnums = {
      arm64_sysreg::ARM64_SYSREG_DCZID_EL0,
      arm64_sysreg::ARM64_SYSREG_FPCR,
      arm64_sysreg::ARM64_SYSREG_FPSR,
      arm64_sysreg::ARM64_SYSREG_TPIDR_EL0,
      arm64_sysreg::ARM64_SYSREG_MIDR_EL1,
      arm64_sysreg::ARM64_SYSREG_CNTVCT_EL0,
      arm64_sysreg::ARM64_SYSREG_PMCCNTR_EL0,
      arm64_sysreg::ARM64_SYSREG_SVCR};
  EXPECT_EQ(simeng::config::SimInfo::getSysRegVec(), sysRegisterEnums);
  std::vector<simeng::RegisterFileStructure> archRegStruct = {
      {8, 32},
      {256, 32},
      {32, 17},
      {1, 1},
      {8, static_cast<uint16_t>(sysRegisterEnums.size())},
      {256, 64}};
  EXPECT_EQ(simeng::config::SimInfo::getArchRegStruct(), archRegStruct);

  // Test that default config generated matches for AArch64 ISA
  std::string emittedConfig =
      ryml::emitrs_yaml<std::string>(simeng::config::SimInfo::getConfig());
  std::string expectedValues =
      "Core:\n  ISA: AArch64\n  'Simulation-Mode': emulation\n  "
      "'Clock-Frequency': 1\n  'Timer-Frequency': 100\n  'Micro-Operations': "
      "0\n  'Vector-Length': 512\n  'Streaming-Vector-Length': 512\nFetch:\n  "
      "'Fetch-Block-Size': 32\n  'Loop-Buffer-Size': 32\n  "
      "'Loop-Detection-Threshold': 5\n'Process-Image':\n  'Heap-Size': "
      "100000\n  'Stack-Size': 100000\n'Register-Set':\n  "
      "'GeneralPurpose-Count': 32\n  'FloatingPoint/SVE-Count': 32\n  "
      "'Predicate-Count': 17\n  'Conditional-Count': 1\n  'Matrix-Count': "
      "1\n'Pipeline-Widths':\n  Commit: 1\n  FrontEnd: 1\n  'LSQ-Completion': "
      "1\n'Queue-Sizes':\n  ROB: 32\n  Load: 16\n  Store: "
      "16\n'Branch-Predictor':\n  'BTB-Tag-Bits': 8\n  "
      "'Saturating-Count-Bits': 2\n  'Global-History-Length': 8\n  "
      "'RAS-entries': 8\n  'Fallback-Static-Predictor': "
      "'Always-Taken'\n'L1-Data-Memory':\n  'Interface-Type': "
      "Flat\n'L1-Instruction-Memory':\n  'Interface-Type': "
      "Flat\n'LSQ-L1-Interface':\n  'Access-Latency': 4\n  Exclusive: 0\n  "
      "'Load-Bandwidth': 32\n  'Store-Bandwidth': 32\n  "
      "'Permitted-Requests-Per-Cycle': 1\n  'Permitted-Loads-Per-Cycle': 1\n  "
      "'Permitted-Stores-Per-Cycle': 1\nPorts:\n  0:\n    Portname: 0\n    "
      "'Instruction-Group-Support':\n      - ALL\n    "
      "'Instruction-Opcode-Support':\n      - 6343\n    "
      "'Instruction-Group-Support-Nums':\n      - "
      "86\n'Reservation-Stations':\n  0:\n    Size: 32\n    'Dispatch-Rate': "
      "4\n    Ports:\n      - 0\n    'Port-Nums':\n      - "
      "0\n'Execution-Units':\n  0:\n    Pipelined: 1\n    'Blocking-Groups':\n "
      "     - NONE\n    'Blocking-Group-Nums':\n      - 87\nLatencies:\n  0:\n "
      "   'Instruction-Groups':\n      - NONE\n    'Instruction-Opcodes':\n    "
      "  - 6343\n    'Execution-Latency': 1\n    'Execution-Throughput': 1\n   "
      " 'Instruction-Group-Nums':\n      - 87\n'CPU-Info':\n  "
      "'Generate-Special-Dir': 0\n  'Core-Count': 1\n  'Socket-Count': 1\n  "
      "SMT: 1\n  BogoMIPS: 0\n  Features: ''\n  'CPU-Implementer': 0x0\n  "
      "'CPU-Architecture': 0\n  'CPU-Variant': 0x0\n  'CPU-Part': 0x0\n  "
      "'CPU-Revision': 0\n  'Package-Count': 1\n";
  EXPECT_EQ(emittedConfig, expectedValues);

  // Generate default for rv64 ISA
  simeng::config::SimInfo::generateDefault(simeng::config::ISA::RV64);

  // Test SimInfo exposed have correctly changed
  EXPECT_EQ(simeng::config::SimInfo::getISA(), simeng::config::ISA::RV64);
  sysRegisterEnums = {};
  EXPECT_EQ(simeng::config::SimInfo::getSysRegVec(), sysRegisterEnums);
  archRegStruct = {
      {8, 32}, {8, 32}, {8, static_cast<uint16_t>(sysRegisterEnums.size())}};
  EXPECT_EQ(simeng::config::SimInfo::getArchRegStruct(), archRegStruct);

  // Test that default config generated matches for rv64 ISA
  emittedConfig =
      ryml::emitrs_yaml<std::string>(simeng::config::SimInfo::getConfig());
  expectedValues =
      "Core:\n  ISA: rv64\n  'Simulation-Mode': emulation\n  "
      "'Clock-Frequency': 1\n  'Timer-Frequency': 100\n  'Micro-Operations': "
      "0\nFetch:\n  'Fetch-Block-Size': 32\n  'Loop-Buffer-Size': 32\n  "
      "'Loop-Detection-Threshold': 5\n'Process-Image':\n  'Heap-Size': "
      "100000\n  'Stack-Size': 100000\n'Register-Set':\n  "
      "'GeneralPurpose-Count': 32\n  "
      "'FloatingPoint-Count': 32\n'Pipeline-Widths':\n  Commit: 1\n  FrontEnd: "
      "1\n  'LSQ-Completion': 1\n'Queue-Sizes':\n  ROB: 32\n  Load: 16\n  "
      "Store: 16\n'Branch-Predictor':\n  'BTB-Tag-Bits': 8\n  "
      "'Saturating-Count-Bits': 2\n  'Global-History-Length': 8\n  "
      "'RAS-entries': 8\n  'Fallback-Static-Predictor': "
      "'Always-Taken'\n'L1-Data-Memory':\n  'Interface-Type': "
      "Flat\n'L1-Instruction-Memory':\n  'Interface-Type': "
      "Flat\n'LSQ-L1-Interface':\n  'Access-Latency': 4\n  Exclusive: 0\n  "
      "'Load-Bandwidth': 32\n  'Store-Bandwidth': 32\n  "
      "'Permitted-Requests-Per-Cycle': 1\n  'Permitted-Loads-Per-Cycle': 1\n  "
      "'Permitted-Stores-Per-Cycle': 1\nPorts:\n  0:\n    Portname: 0\n    "
      "'Instruction-Group-Support':\n      - ALL\n    "
      "'Instruction-Opcode-Support':\n      - 450\n    "
      "'Instruction-Group-Support-Nums':\n      - "
      "13\n'Reservation-Stations':\n  0:\n    Size: 32\n    'Dispatch-Rate': "
      "4\n    Ports:\n      - 0\n    'Port-Nums':\n      - "
      "0\n'Execution-Units':\n  0:\n    Pipelined: 1\n    'Blocking-Groups':\n "
      "     - NONE\n    'Blocking-Group-Nums':\n      - 14\nLatencies:\n  0:\n "
      "   'Instruction-Groups':\n      - NONE\n    'Instruction-Opcodes':\n    "
      "  - 450\n    'Execution-Latency': 1\n    'Execution-Throughput': 1\n    "
      "'Instruction-Group-Nums':\n      - 14\n'CPU-Info':\n  "
      "'Generate-Special-Dir': 0\n  'Core-Count': 1\n  'Socket-Count': 1\n  "
      "SMT: 1\n  BogoMIPS: 0\n  Features: ''\n  'CPU-Implementer': 0x0\n  "
      "'CPU-Architecture': 0\n  'CPU-Variant': 0x0\n  'CPU-Part': 0x0\n  "
      "'CPU-Revision': 0\n  'Package-Count': 1\n";
  EXPECT_EQ(emittedConfig, expectedValues);
}

TEST(ConfigTest, GetValue) {
  simeng::config::SimInfo::generateDefault(simeng::config::ISA::AArch64);
  ryml::ConstNodeRef config = simeng::config::SimInfo::getConfig();
  // Test that getting values from the config returns the correct values
  EXPECT_EQ(
      simeng::config::SimInfo::getValue<std::string>(config["Core"]["ISA"]),
      "AArch64");
  EXPECT_EQ(simeng::config::SimInfo::getValue<float>(
                config["Core"]["Clock-Frequency"]),
            1.f);
  EXPECT_EQ(simeng::config::SimInfo::getValue<uint64_t>(
                config["Core"]["Timer-Frequency"]),
            100);
  EXPECT_EQ(simeng::config::SimInfo::getValue<bool>(
                config["Core"]["Micro-Operations"]),
            false);
}

TEST(ConfigTest, AddConfigValues) {
  // Test that editting existing and adding new values is correct
  simeng::config::SimInfo::addToConfig("{Core: {Simulation-Mode: outoforder}}");
  simeng::config::SimInfo::addToConfig("{Core: {Key: Value}}");
  simeng::config::SimInfo::addToConfig("{TestA: {Key: Value}}");
  simeng::config::SimInfo::addToConfig("{Core: {Seq: [0, 1, 2]}}");
  simeng::config::SimInfo::addToConfig("{TestB: {Seq: [0, 1, 2]}}");
  simeng::config::SimInfo::addToConfig(
      "{Ports: {1: {Portname: Port 1, Instruction-Group-Support: [BRANCH]}}, "
      "Reservation-Stations: {1: {Size: 32, Dispatch-Rate: 1, Ports: [Port "
      "1]}}, Execution-Units: {1: {Pipelined: False}}}");

  ryml::ConstNodeRef config = simeng::config::SimInfo::getConfig();
  EXPECT_EQ(simeng::config::SimInfo::getValue<std::string>(
                config["Core"]["Simulation-Mode"]),
            "outoforder");
  EXPECT_EQ(
      simeng::config::SimInfo::getValue<std::string>(config["Core"]["Key"]),
      "Value");
  EXPECT_EQ(
      simeng::config::SimInfo::getValue<std::string>(config["TestA"]["Key"]),
      "Value");

  EXPECT_EQ(
      simeng::config::SimInfo::getValue<uint8_t>(config["Core"]["Seq"][0]), 0);
  EXPECT_EQ(
      simeng::config::SimInfo::getValue<uint8_t>(config["Core"]["Seq"][1]), 1);
  EXPECT_EQ(
      simeng::config::SimInfo::getValue<uint8_t>(config["Core"]["Seq"][2]), 2);

  EXPECT_EQ(
      simeng::config::SimInfo::getValue<uint8_t>(config["TestB"]["Seq"][0]), 0);
  EXPECT_EQ(
      simeng::config::SimInfo::getValue<uint8_t>(config["TestB"]["Seq"][1]), 1);
  EXPECT_EQ(
      simeng::config::SimInfo::getValue<uint8_t>(config["TestB"]["Seq"][2]), 2);

  EXPECT_EQ(config["Ports"].num_children(), 2);
  EXPECT_EQ(config["Reservation-Stations"].num_children(), 2);
  EXPECT_EQ(config["Execution-Units"].num_children(), 2);
}

TEST(ConfigTest, FailedExpectation) {
  simeng::config::SimInfo::generateDefault(simeng::config::ISA::AArch64, true);
  // Test that adding an invalid entry fails the config validation
  ASSERT_DEATH(
      {
        simeng::config::SimInfo::addToConfig(
            "{Core: {Simulation-Mode: wrong}}");
      },
      "- Core:Simulation-Mode wrong not in set");
  ASSERT_DEATH(
      {
        simeng::config::SimInfo::addToConfig(
            "{Reservation-Stations: {1: {Size: "
            "32, Dispatch-Rate: 1}}}");
      },
      "- Reservation-Stations:1:Ports has no value");
  ASSERT_DEATH(
      {
        simeng::config::SimInfo::addToConfig(
            "{Reservation-Stations: {1: {Size: "
            "32, Dispatch-Rate: 1, Ports: [WRONG]}}}");
      },
      "- Reservation-Stations:1:Ports:0 WRONG not in set");

  // Test for post validation checks are triggered
  ASSERT_DEATH(
      {
        simeng::config::SimInfo::addToConfig(
            "{CPU-Info: {Package-Count: 10, Core-Count: 3}}");
      },
      "- Package-Count must be a Less-than or equal to Core-Count, and "
      "Core-Count must be divisible by Package-Count");
  ASSERT_DEATH(
      {
        simeng::config::SimInfo::addToConfig(
            "{Ports: {1: {Portname: Port 1}}}");
      },
      "- The number of execution units \\(1\\) must match the number of ports "
      "\\(2\\)");
  ASSERT_DEATH(
      {
        simeng::config::SimInfo::addToConfig(
            "{Ports: {1: {Portname: Port 1}}, Execution-Units: {1: {Pipelined "
            ": False}}}");
      },
      "- Port 1 has no associated reservation station");
}

}  // namespace
