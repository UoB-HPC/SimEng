#include "gtest/gtest.h"
#include "simeng/ModelConfig.hh"
#include "simeng/kernel/LinuxProcess.hh"
#include "simeng/version.hh"

namespace simeng {

class ProcessTest : public testing::Test {
 public:
  ProcessTest()
      : config(simeng::ModelConfig(SIMENG_SOURCE_DIR "/configs/a64fx.yaml")
                   .getConfigFile()) {}

 protected:
  YAML::Node config;
  const std::vector<std::string> cmdLine = {
      SIMENG_SOURCE_DIR "/test/unit/data/stream-aarch64.elf"};

  // Program used when no executable is provided; counts down from
  // 1024*1024, with an independent `orr` at the start of each branch.
  uint32_t demoHex[7] = {
      0x320C03E0,  // orr w0, wzr, #1048576
      0x320003E1,  // orr w0, wzr, #1
      0x71000400,  // subs w0, w0, #1
      0x54FFFFC1,  // b.ne -8
                   // .exit:
      0xD2800000,  // mov x0, #0
      0xD2800BC8,  // mov x8, #94
      0xD4000001,  // svc #0
  };
};

TEST_F(ProcessTest, alignToBoundary) {
  EXPECT_EQ(kernel::alignToBoundary(63, 64), 64);
  EXPECT_EQ(kernel::alignToBoundary(1, 64), 64);
  EXPECT_EQ(kernel::alignToBoundary(65, 64), 128);
}

// Tests createProcess(), isValid(), and getPath() functions.
TEST_F(ProcessTest, createProcess_elf) {
  kernel::LinuxProcess proc = kernel::LinuxProcess(cmdLine, config);
  EXPECT_TRUE(proc.isValid());
  EXPECT_EQ(proc.getPath(),
            SIMENG_SOURCE_DIR "/test/unit/data/stream-aarch64.elf");
}

// Tests createProcess(), isValid(), and getPath() functions.
TEST_F(ProcessTest, createProcess_hex) {
  kernel::LinuxProcess proc = kernel::LinuxProcess(
      span(reinterpret_cast<char*>(demoHex), sizeof(demoHex)), config);
  EXPECT_TRUE(proc.isValid());
  EXPECT_EQ(proc.getPath(), "\0");
}

// Tests get{Heap, Stack, Mmap}Start() functions
TEST_F(ProcessTest, get_x_Start) {
  kernel::LinuxProcess proc = kernel::LinuxProcess(cmdLine, config);
  EXPECT_TRUE(proc.isValid());
  uint64_t heapStart = 5040480;
  uint64_t heapSize = config["Process-Image"]["Heap-Size"].as<uint64_t>();
  uint64_t stackSize = config["Process-Image"]["Stack-Size"].as<uint64_t>();
  EXPECT_EQ(proc.getHeapStart(), heapStart);
  EXPECT_EQ(proc.getMmapStart(),
            kernel::alignToBoundary(heapStart + ((heapSize + stackSize) / 2),
                                    proc.getPageSize()));
  EXPECT_EQ(proc.getStackStart(), heapStart + heapSize + stackSize);
}

TEST_F(ProcessTest, getPageSize) {
  kernel::LinuxProcess proc = kernel::LinuxProcess(cmdLine, config);
  EXPECT_TRUE(proc.isValid());
  EXPECT_EQ(proc.getPageSize(), 4096);
}

TEST_F(ProcessTest, getProcessImage) {
  kernel::LinuxProcess proc = kernel::LinuxProcess(cmdLine, config);
  EXPECT_TRUE(proc.isValid());
  EXPECT_NE(proc.getProcessImage(), nullptr);
}

TEST_F(ProcessTest, getProcessImageSize) {
  kernel::LinuxProcess proc = kernel::LinuxProcess(cmdLine, config);
  EXPECT_TRUE(proc.isValid());
  EXPECT_GT(proc.getProcessImageSize(), 0);
}

TEST_F(ProcessTest, getEntryPoint) {
  kernel::LinuxProcess proc = kernel::LinuxProcess(cmdLine, config);
  EXPECT_TRUE(proc.isValid());
  EXPECT_EQ(proc.getEntryPoint(), 4206008);
}

TEST_F(ProcessTest, getStackPointer) {
  kernel::LinuxProcess proc = kernel::LinuxProcess(cmdLine, config);
  EXPECT_TRUE(proc.isValid());
  // cmdLine[0] length will change depending on the host system so final stack
  // pointer needs to be calculated, and need to add +1 for the null char at end
  // of a string
  EXPECT_EQ(proc.getStackPointer(), 1079830551 + cmdLine[0].length() + 1);
}

}  // namespace simeng

// getEntryPoint
// getStackPointer