#include "ConfigInit.hh"
#include "gmock/gmock.h"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/version.hh"

namespace simeng {

#define TEST_SPEC_FILE_DIR SIMENG_SOURCE_DIR "/test/unit/specialFiles/"

class SpecialFileDirGenTest : public testing::Test {
 public:
  SpecialFileDirGenTest() {}

 protected:
  ConfigInit configInit = ConfigInit(config::ISA::AArch64,
                                     R"YAML({
        CPU-Info: {
          Generate-Special-Dir: True,
          Special-File-Dir-Path: )YAML" TEST_SPEC_FILE_DIR R"YAML(,
          Core-Count: 1,
          Socket-Count: 1,
          SMT: 1,
          BogoMIPS: 200.00,
          Features: fp asimd evtstrm sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm fcma dcpop sve,
          CPU-Implementer: 0x46,
          CPU-Architecture: 8,
          CPU-Variant: 0x1,
          CPU-Part: 0x001,
          CPU-Revision: 0,
          Package-Count: 1
        }
      })YAML");

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
    EXPECT_FALSE(
        std::ifstream(TEST_SPEC_FILE_DIR + std::get<0>(allFiles_names_Lines[i]))
            .good());
  }

  // Generate files
  specFile.GenerateSFDir();

  // Validate files exist and are correct
  for (int i = 0; i < allFiles_names_Lines.size(); i++) {
    EXPECT_TRUE(
        std::ifstream(TEST_SPEC_FILE_DIR + std::get<0>(allFiles_names_Lines[i]))
            .good());
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
    EXPECT_FALSE(
        std::ifstream(TEST_SPEC_FILE_DIR + std::get<0>(allFiles_names_Lines[i]))
            .good());
  }
}

// Test that a non-existant non-default special file directory causes the user
// to be notified when generation is set to False
TEST_F(SpecialFileDirGenTest, doesntExist) {
  // Reset SimInfo Config
  ASSERT_DEATH(
      config::SimInfo::addToConfig(
          "CPU-Info: {Generate-Special-Dir: False, "
          "Special-File-Dir-Path: " SIMENG_BUILD_DIR "/thisDoesntExistDir/"
          ", Core-Count: 1, Socket-Count: 1, SMT: 1, BogoMIPS: 200.00, "
          "Features: "
          "fp asimd evtstrm sha1 sha2 crc32 atomics fphp asimdhp cpuid "
          "asimdrdm "
          "fcma dcpop sve, CPU-Implementer: 0x46, CPU-Architecture: 8, "
          "CPU-Variant: 0x1, CPU-Part: 0x001, CPU-Revision: 0, Package-Count: "
          "1}}"),
      "- Special File Directory '" SIMENG_BUILD_DIR
      "/thisDoesntExistDir/' does not exist");
}

}  // namespace simeng