#include "gmock/gmock.h"
#include "simeng/Elf.hh"
#include "simeng/version.hh"

using ::testing::_;
using ::testing::HasSubstr;
using ::testing::Return;

namespace simeng {

class ElfTest : public testing::Test {
 public:
  ElfTest() {}

 protected:
  const std::string knownElfFilePath =
      SIMENG_SOURCE_DIR "/test/unit/data/stream-aarch64.elf";

  const uint64_t known_entryPoint = 4206008;
  const uint16_t known_e_phentsize = 56;
  const uint16_t known_e_phnum = 6;
  const uint64_t known_phdrTableAddress = 4194368;
  const uint64_t known_processImageSize = 5040480;

  char* unwrappedProcImgPtr;
};

// Test that a valid ELF file can be created
TEST_F(ElfTest, validElf) {
  Elf elf(knownElfFilePath, &unwrappedProcImgPtr);

  EXPECT_TRUE(elf.isValid());
  EXPECT_EQ(elf.getEntryPoint(), known_entryPoint);
  EXPECT_EQ(elf.getPhdrEntrySize(), known_e_phentsize);
  EXPECT_EQ(elf.getNumPhdr(), known_e_phnum);
  EXPECT_EQ(elf.getPhdrTableAddress(), known_phdrTableAddress);
  EXPECT_EQ(elf.getProcessImageSize(), known_processImageSize);
}

// Test that wrong filepath results in invalid ELF
TEST_F(ElfTest, invalidElf) {
  Elf elf(SIMENG_SOURCE_DIR "/test/bogus_file_path___--__--__",
          &unwrappedProcImgPtr);
  EXPECT_FALSE(elf.isValid());
}

// Test that non-ELF file is not accepted
TEST_F(ElfTest, nonElf) {
  testing::internal::CaptureStderr();
  Elf elf(SIMENG_SOURCE_DIR "/test/unit/ElfTest.cc", &unwrappedProcImgPtr);
  EXPECT_FALSE(elf.isValid());
  EXPECT_THAT(testing::internal::GetCapturedStderr(),
              HasSubstr("[SimEng:Elf] Elf magic does not match"));
}

// Check that 32-bit ELF is not accepted
TEST_F(ElfTest, format32Elf) {
  testing::internal::CaptureStderr();
  Elf elf(SIMENG_SOURCE_DIR "/test/unit/data/stream.rv32ima.elf",
          &unwrappedProcImgPtr);
  EXPECT_FALSE(elf.isValid());
  EXPECT_THAT(
      testing::internal::GetCapturedStderr(),
      HasSubstr("[SimEng:Elf] Unsupported architecture detected in Elf"));
}

}  // namespace simeng