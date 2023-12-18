#include <fstream>
#include <iostream>

#include "gtest/gtest.h"
#include "simeng/config/SimInfo.hh"
#include "simeng/version.hh"

namespace {

// Test generated default values are correct
TEST(ConfigTest, Default) {
  // Test key default values exposed in SimInfo
  EXPECT_EQ(simeng::config::SimInfo::getConfigPath(), "Default");
  EXPECT_EQ(simeng::config::SimInfo::getISA(), simeng::config::ISA::AArch64);
  EXPECT_EQ(simeng::config::SimInfo::getSimMode(),
            simeng::config::SimulationMode::Emulation);
  EXPECT_EQ(simeng::config::SimInfo::getSimModeStr(), "Emulation");
  std::vector<uint64_t> sysRegisterEnums = {
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
      {256, 16}};
  EXPECT_EQ(simeng::config::SimInfo::getArchRegStruct(), archRegStruct);

  // Test that default config generated matches for AArch64 ISA
  std::string emittedConfig =
      ryml::emitrs_yaml<std::string>(simeng::config::SimInfo::getConfig());
  std::string expectedValues =
      "Core:\n  ISA: AArch64\n  'Simulation-Mode': emulation\n  "
      "'Clock-Frequency-GHz': 1\n  'Timer-Frequency-MHz': 100\n  "
      "'Micro-Operations': 0\n  'Vector-Length': 128\n  "
      "'Streaming-Vector-Length': 128\nFetch:\n  'Fetch-Block-Size': 32\n  "
      "'Loop-Buffer-Size': 32\n  'Loop-Detection-Threshold': "
      "5\n'Process-Image':\n  'Heap-Size': 100000\n  'Stack-Size': "
      "100000\n'Register-Set':\n  'GeneralPurpose-Count': 32\n  "
      "'FloatingPoint/SVE-Count': 32\n  'Predicate-Count': 17\n  "
      "'Conditional-Count': 1\n  'Matrix-Count': 1\n'Pipeline-Widths':\n  "
      "Commit: 1\n  FrontEnd: 1\n  'LSQ-Completion': 1\n'Queue-Sizes':\n  ROB: "
      "32\n  Load: 16\n  Store: 16\n'Branch-Predictor':\n  'BTB-Tag-Bits': 8\n "
      " 'Saturating-Count-Bits': 2\n  'Global-History-Length': 8\n  "
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
      "'Generate-Special-Dir': 0\n  'Special-File-Dir-Path': " SIMENG_BUILD_DIR
      "/specialFiles/\n  'Core-Count': 1\n  'Socket-Count': 1\n  "
      "SMT: 1\n  BogoMIPS: 0\n  Features: ''\n  'CPU-Implementer': 0x0\n  "
      "'CPU-Architecture': 0\n  'CPU-Variant': 0x0\n  'CPU-Part': 0x0\n  "
      "'CPU-Revision': 0\n  'Package-Count': 1\n";
  EXPECT_EQ(emittedConfig, expectedValues);

  // Generate default for rv64 ISA
  simeng::config::SimInfo::generateDefault(simeng::config::ISA::RV64);

  // Test SimInfo exposed have correctly changed
  EXPECT_EQ(simeng::config::SimInfo::getISA(), simeng::config::ISA::RV64);
  sysRegisterEnums = {simeng::arch::riscv::riscv_sysreg::RISCV_SYSREG_FFLAGS,
                      simeng::arch::riscv::riscv_sysreg::RISCV_SYSREG_FRM,
                      simeng::arch::riscv::riscv_sysreg::RISCV_SYSREG_FCSR,
                      simeng::arch::riscv::riscv_sysreg::RISCV_SYSREG_CYCLE,
                      simeng::arch::riscv::riscv_sysreg::RISCV_SYSREG_TIME,
                      simeng::arch::riscv::riscv_sysreg::RISCV_SYSREG_INSTRET};
  EXPECT_EQ(simeng::config::SimInfo::getSysRegVec(), sysRegisterEnums);
  archRegStruct = {
      {8, 32}, {8, 32}, {8, static_cast<uint16_t>(sysRegisterEnums.size())}};
  EXPECT_EQ(simeng::config::SimInfo::getArchRegStruct(), archRegStruct);

  // Test that default config generated matches for rv64 ISA
  emittedConfig =
      ryml::emitrs_yaml<std::string>(simeng::config::SimInfo::getConfig());
  expectedValues =
      "Core:\n  ISA: rv64\n  'Simulation-Mode': emulation\n  "
      "'Clock-Frequency-GHz': 1\n  'Timer-Frequency-MHz': 100\n  "
      "'Micro-Operations': 0\nFetch:\n  'Fetch-Block-Size': 32\n  "
      "'Loop-Buffer-Size': 32\n  'Loop-Detection-Threshold': "
      "5\n'Process-Image':\n  'Heap-Size': 100000\n  'Stack-Size': "
      "100000\n'Register-Set':\n  'GeneralPurpose-Count': 32\n  "
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
      "23\n'Reservation-Stations':\n  0:\n    Size: 32\n    'Dispatch-Rate': "
      "4\n    Ports:\n      - 0\n    'Port-Nums':\n      - "
      "0\n'Execution-Units':\n  0:\n    Pipelined: 1\n    'Blocking-Groups':\n "
      "     - NONE\n    'Blocking-Group-Nums':\n      - 24\nLatencies:\n  0:\n "
      "   'Instruction-Groups':\n      - NONE\n    'Instruction-Opcodes':\n    "
      "  - 450\n    'Execution-Latency': 1\n    'Execution-Throughput': 1\n    "
      "'Instruction-Group-Nums':\n      - 24\n'CPU-Info':\n  "
      "'Generate-Special-Dir': 0\n  'Special-File-Dir-Path': " SIMENG_BUILD_DIR
      "/specialFiles/\n  'Core-Count': 1\n  'Socket-Count': 1\n  "
      "SMT: 1\n  BogoMIPS: 0\n  Features: ''\n  'CPU-Implementer': 0x0\n  "
      "'CPU-Architecture': 0\n  'CPU-Variant': 0x0\n  'CPU-Part': 0x0\n  "
      "'CPU-Revision': 0\n  'Package-Count': 1\n";
  EXPECT_EQ(emittedConfig, expectedValues);
}

// Test that getting values from the config returns the correct values
TEST(ConfigTest, as) {
  simeng::config::SimInfo::generateDefault(simeng::config::ISA::AArch64);
  ryml::ConstNodeRef config = simeng::config::SimInfo::getConfig();
  EXPECT_EQ(config["Core"]["ISA"].as<std::string>(), "AArch64");
  EXPECT_EQ(config["Core"]["Clock-Frequency-GHz"].as<float>(), 1.f);
  EXPECT_EQ(config["Core"]["Timer-Frequency-MHz"].as<uint64_t>(), 100);
  EXPECT_EQ(config["Core"]["Micro-Operations"].as<bool>(), false);
}

// Test that editting existing and adding new values is correct
TEST(ConfigTest, AddConfigValues) {
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
  EXPECT_EQ(config["Core"]["Simulation-Mode"].as<std::string>(), "outoforder");
  EXPECT_EQ(config["Core"]["Key"].as<std::string>(), "Value");
  EXPECT_EQ(config["TestA"]["Key"].as<std::string>(), "Value");

  EXPECT_EQ(config["Core"]["Seq"][0].as<uint8_t>(), 0);
  EXPECT_EQ(config["Core"]["Seq"][1].as<uint8_t>(), 1);
  EXPECT_EQ(config["Core"]["Seq"][2].as<uint8_t>(), 2);

  EXPECT_EQ(config["TestB"]["Seq"][0].as<uint8_t>(), 0);
  EXPECT_EQ(config["TestB"]["Seq"][1].as<uint8_t>(), 1);
  EXPECT_EQ(config["TestB"]["Seq"][2].as<uint8_t>(), 2);

  EXPECT_EQ(config["Ports"].num_children(), 2);
  EXPECT_EQ(config["Reservation-Stations"].num_children(), 2);
  EXPECT_EQ(config["Execution-Units"].num_children(), 2);
}

// Test that adding an invalid entry fails the config validation
TEST(ConfigTest, FailedExpectation) {
  simeng::config::SimInfo::generateDefault(simeng::config::ISA::AArch64, true);
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

// Test that ExpectationNode validation checks work as expected
TEST(ConfigTest, validation) {
  simeng::config::ExpectationNode expectations =
      simeng::config::ExpectationNode();
  expectations.addChild(
      simeng::config::ExpectationNode::createExpectation("HEAD"));
  expectations["HEAD"].addChild(
      simeng::config::ExpectationNode::createExpectation<bool>(true,
                                                               "CHILD_BOOL"));
  expectations["HEAD"]["CHILD_BOOL"].setValueSet<bool>({false});
  expectations["HEAD"].addChild(
      simeng::config::ExpectationNode::createExpectation<float>(123.456f,
                                                                "CHILD_FLOAT"));
  expectations["HEAD"]["CHILD_FLOAT"].setValueBounds<float>(456.789f, 789.456f);
  expectations["HEAD"].addChild(
      simeng::config::ExpectationNode::createExpectation<std::string>(
          "STR", "CHILD_STRING"));
  expectations["HEAD"]["CHILD_STRING"].setValueSet<std::string>(
      {"HELLO", "WORLD", "SIMENG"});
  expectations["HEAD"].addChild(
      simeng::config::ExpectationNode::createExpectation<uint64_t>(
          333, "CHILD_UINT"));
  expectations["HEAD"]["CHILD_UINT"].setValueBounds<uint64_t>(345, 678);

  ryml::Tree tree;
  tree.rootref() |= ryml::MAP;
  ryml::NodeRef ref;
  size_t id = tree.root_id();
  tree.ref(id).append_child() << ryml::key("noVal");
  ref = tree.ref(id).append_child() << ryml::key("bool");
  ref << true;
  ref = tree.ref(id).append_child() << ryml::key("float");
  ref << 123.456f;
  ref = tree.ref(id).append_child() << ryml::key("string");
  ref << "STR";
  ref = tree.ref(id).append_child() << ryml::key("uint");
  ref << 333;

  EXPECT_EQ(expectations["HEAD"]["CHILD_BOOL"]
                .validateConfigNode(tree.rootref()["bool"])
                .message,
            "1 not in set {0}");
  EXPECT_EQ(expectations["HEAD"]["CHILD_FLOAT"]
                .validateConfigNode(tree.rootref()["float"])
                .message,
            "123.456 not in the bounds {456.789 to 789.456}");
  EXPECT_EQ(expectations["HEAD"]["CHILD_STRING"]
                .validateConfigNode(tree.rootref()["string"])
                .message,
            "STR not in set {HELLO, WORLD, SIMENG}");
  EXPECT_EQ(expectations["HEAD"]["CHILD_UINT"]
                .validateConfigNode(tree.rootref()["uint"])
                .message,
            "333 not in the bounds {345 to 678}");
}

// Test that calling setValueBounds() with the wrong data type fails
TEST(ConfigTest, invalidTypeOnValueBounds) {
  simeng::config::ExpectationNode expectations =
      simeng::config::ExpectationNode();
  expectations.addChild(
      simeng::config::ExpectationNode::createExpectation("HEAD"));
  expectations["HEAD"].addChild(
      simeng::config::ExpectationNode::createExpectation<std::string>("DEFAULT",
                                                                      "CHILD"));
  ASSERT_DEATH(
      { expectations["HEAD"]["CHILD"].setValueBounds<uint32_t>(0, 10); },
      "The data type of the passed value bounds used in setValueBounds\\() "
      "does not match that held within the ExpectationNode with key "
      "HEAD:CHILD. Passed bounds are of type 32-bit unsigned integer and the "
      "expected type of this node is string.");
}

// Test that calling setValueSet() with the wrong data type fails
TEST(ConfigTest, invalidTypeOnSetBounds) {
  simeng::config::ExpectationNode expectations =
      simeng::config::ExpectationNode();
  expectations.addChild(
      simeng::config::ExpectationNode::createExpectation("HEAD"));
  expectations["HEAD"].addChild(
      simeng::config::ExpectationNode::createExpectation<std::string>("DEFAULT",
                                                                      "CHILD"));
  ASSERT_DEATH(
      {
        expectations["HEAD"]["CHILD"].setValueSet<int32_t>({0, 1, 2});
      },
      "The data type of the passed vector used in setValueSet\\() "
      "does not match that held within the ExpectationNode with key "
      "HEAD:CHILD. Passed vector elements are of type 32-bit integer and the "
      "expected type of this node is string.");
}

// Test that calling setValueSet() after an expectation value set has already
// been defined fails
TEST(ConfigTest, alreadyDefinedBounds) {
  simeng::config::ExpectationNode expectations =
      simeng::config::ExpectationNode();
  expectations.addChild(
      simeng::config::ExpectationNode::createExpectation("HEAD"));
  expectations["HEAD"].addChild(
      simeng::config::ExpectationNode::createExpectation<uint64_t>(0, "CHILD"));
  expectations["HEAD"]["CHILD"].setValueBounds<uint64_t>(0, 10);
  ASSERT_DEATH(
      {
        expectations["HEAD"]["CHILD"].setValueSet<uint64_t>({1, 2, 3});
      },
      "Invalid call of setValueSet\\() for the ExpectationNode with key "
      "HEAD:CHILD as value bounds have already been defined.");
}

// Test that calling setValueBounds() after expectation value bounds have
// already been defined fails
TEST(ConfigTest, alreadyDefinedSet) {
  simeng::config::ExpectationNode expectations =
      simeng::config::ExpectationNode();
  expectations.addChild(
      simeng::config::ExpectationNode::createExpectation("HEAD"));
  expectations["HEAD"].addChild(
      simeng::config::ExpectationNode::createExpectation<uint64_t>(0, "CHILD"));
  expectations["HEAD"]["CHILD"].setValueSet<uint64_t>({1, 2, 3});
  ASSERT_DEATH(
      { expectations["HEAD"]["CHILD"].setValueBounds<uint64_t>(0, 10); },
      "Invalid call of setValueBounds\\() for the ExpectationNode with "
      "key HEAD:CHILD as a value set has already been defined.");
}

// Test that adding multiple wild ExpectationNodes to the same parent fails
TEST(ConfigTest, multipleWildNodes) {
  simeng::config::ExpectationNode expectations =
      simeng::config::ExpectationNode();
  expectations.addChild(
      simeng::config::ExpectationNode::createExpectation("HEAD"));
  expectations["HEAD"].addChild(
      simeng::config::ExpectationNode::createExpectation(
          simeng::config::wildcard));
  ASSERT_DEATH(
      {
        expectations["HEAD"].addChild(
            simeng::config::ExpectationNode::createExpectation(
                simeng::config::wildcard));
      },
      "Attempted to add multiple wildcard nodes to the same ExpectationNode "
      "instance of key HEAD");
}

}  // namespace
