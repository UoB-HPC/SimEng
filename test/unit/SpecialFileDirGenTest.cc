#include <filesystem>

#include "gmock/gmock.h"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/version.hh"

namespace simeng {

#define TEST_SPEC_FILE_DIR SIMENG_SOURCE_DIR "/test/unit/specialFiles/"

#define SPEC_FILE_TEST_CONFIG                                                  \
  ("{Core: {ISA: AArch64, Simulation-Mode: inorderpipelined, "                 \
   "Clock-Frequency: 2.5, Timer-Frequency: 100, Micro-Operations: True, "      \
   "Vector-Length: 512, Streaming-Vector-Length: 512}, Fetch: "                \
   "{Fetch-Block-Size: 32, Loop-Buffer-Size: 64, Loop-Detection-Threshold: "   \
   "4}, Process-Image: {Heap-Size: 10485760, Stack-Size: 1048576}, "           \
   "Register-Set: {GeneralPurpose-Count: 154, FloatingPoint/SVE-Count: 90, "   \
   "Predicate-Count: 17, Conditional-Count: 128, Matrix-Count: 2}, "           \
   "Pipeline-Widths: {Commit: 4, FrontEnd: 4, LSQ-Completion: 2}, "            \
   "Queue-Sizes: {ROB: 180, Load: 64, Store: 36}, Branch-Predictor: "          \
   "{BTB-Tag-Bits: 11, Saturating-Count-Bits: 2, Global-History-Length: 10, "  \
   "RAS-entries: 5, Fallback-Static-Predictor: 2}, L1-Data-Memory: "           \
   "{Interface-Type: Flat}, L1-Instruction-Memory: {Interface-Type: Flat}, "   \
   "LSQ-L1-Interface: {Access-Latency: 4, Exclusive: False, Load-Bandwidth: "  \
   "32, Store-Bandwidth: 16, Permitted-Requests-Per-Cycle: 2, "                \
   "Permitted-Loads-Per-Cycle: 2, Permitted-Stores-Per-Cycle: 1}, Ports: "     \
   "{'0': {Portname: Port 0, Instruction-Group-Support: [1, 8, 14]}, '1': "    \
   "{Portname: Port 1, Instruction-Group-Support: [0, 14]}, '2': {Portname: "  \
   "Port 2, Instruction-Group-Support: [1, 8, 71]}, '3': {Portname: Port 4, "  \
   "Instruction-Group-Support: [67]}, '4': {Portname: Port 5, "                \
   "Instruction-Group-Support: [67]}, '5': {Portname: Port 3, "                \
   "Instruction-Group-Support: [70]}}, Reservation-Stations: {'0': {Size: "    \
   "60, Dispatch-Rate: 4, Ports: [0, 1, 2, 3, 4, 5]}}, Execution-Units: "      \
   "{'0': {Pipelined: true}, '1': {Pipelined: true}, '2': {Pipelined: true}, " \
   "'3': {Pipelined:true}, '4': {Pipelined: true}, '5': {Pipelined: true}}, "  \
   "CPU-Info: {Generate-Special-Dir: True, "                                   \
   "Special-File-Dir-Path: " TEST_SPEC_FILE_DIR                                \
   ", Core-Count: 1, Socket-Count: 1, SMT: 1, BogoMIPS: 200.00, Features: fp " \
   "asimd evtstrm sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm fcma "   \
   "dcpop sve, CPU-Implementer: 0x46, CPU-Architecture: 8, CPU-Variant: 0x1, " \
   "CPU-Part: 0x001, CPU-Revision: 0, Package-Count: 1}}")

class SpecialFileDirGenTest : public testing::Test {
 public:
  SpecialFileDirGenTest()
      : config(YAML::Load(SPEC_FILE_TEST_CONFIG)), specFile(config) {}

 protected:
  YAML::Node config;
  SpecialFileDirGen specFile;

  const std::vector<std::pair<std::string, std::vector<std::string>>>
      allFiles_names_Lines = {
          std::pair<std::string, std::vector<std::string>>(
              "proc/cpuinfo",
              {"processor	: 0", "BogoMIPS	: 200.00",
               "Features	: fp asimd evtstrm sha1 sha2 "
               "crc32 atomics fphp asimdhp cpuid "
               "asimdrdm fcma dcpop sve",
               "CPU implementer	: 0x46", "CPU architecture: 8",
               "CPU variant	: 0x1", "CPU part	: 0x001",
               "CPU revision	: 0", ""}),
          std::pair<std::string, std::vector<std::string>>(
              "proc/stat",
              {"cpu  0 0 0 0 0 0 0 0 0 0", "cpu0 0 0 0 0 0 0 0 0 0 0",
               "intr 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
               "0 0 0 0 "
               "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
               "0 0 0 0 0 "
               "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
               "0 0 0 0 0 "
               "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
               "0 0 0 0 0 "
               "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
               "0 0 0 0 0 "
               "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
               "ctxt 0", "btime 0", "processes 0", "procs_running 1",
               "procs_blocked 0", "softirq 0 0 0 0 0 0 0 0 0 0 0"}),
          std::pair<std::string, std::vector<std::string>>(
              "sys/devices/system/cpu/cpu0/topology/core_id", {"0"}),
          std::pair<std::string, std::vector<std::string>>(
              "sys/devices/system/cpu/cpu0/topology/physical_package_id",
              {"0"}),
          std::pair<std::string, std::vector<std::string>>(
              "sys/devices/system/cpu/online", {"0-0"})};
};

// Test that we can generate and delete special files to a custom directory
// (i.e. the one defined in the YAML string above)
TEST_F(SpecialFileDirGenTest, genAndDelete) {
  // Make sure files currently do not exist
  for (int i = 0; i < allFiles_names_Lines.size(); i++) {
    EXPECT_FALSE(std::filesystem::exists(TEST_SPEC_FILE_DIR +
                                         std::get<0>(allFiles_names_Lines[i])));
  }

  // Generate files
  specFile.GenerateSFDir();

  // Validate files exist and are correct
  for (int i = 0; i < allFiles_names_Lines.size(); i++) {
    EXPECT_TRUE(std::filesystem::exists(TEST_SPEC_FILE_DIR +
                                        std::get<0>(allFiles_names_Lines[i])));
    std::ifstream file(TEST_SPEC_FILE_DIR +
                       std::get<0>(allFiles_names_Lines[i]));
    const std::vector<std::string>& knownLines =
        std::get<1>(allFiles_names_Lines[i]);
    std::string line;
    int numOfLines = 0;
    while (std::getline(file, line)) {
      if (numOfLines > knownLines.size()) {
        break;
      }
      EXPECT_EQ(line, knownLines[numOfLines]);
      numOfLines++;
    }
    EXPECT_EQ(numOfLines, knownLines.size());
  }

  // Delete files
  specFile.RemoveExistingSFDir();

  // Make sure files don't exist
  for (int i = 0; i < allFiles_names_Lines.size(); i++) {
    EXPECT_FALSE(std::filesystem::exists(TEST_SPEC_FILE_DIR +
                                         std::get<0>(allFiles_names_Lines[i])));
  }
}

}  // namespace simeng