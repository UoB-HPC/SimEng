#include "gtest/gtest.h"
#include "simeng/ModelConfig.hh"
#include "simeng/kernel/Linux.hh"
#include "simeng/kernel/LinuxProcess.hh"
#include "simeng/span.hh"

namespace simeng {

class OSTest : public testing::Test {
 public:
  OSTest()
      : config(simeng::ModelConfig(SIMENG_SOURCE_DIR "/configs/a64fx.yaml")
                   .getConfigFile()),
        proc_elf(simeng::kernel::LinuxProcess(cmdLine, config)),
        proc_hex(simeng::span<char>(reinterpret_cast<char*>(demoHex),
                                    sizeof(demoHex)),
                 config) {}

 protected:
  // Linux class is ISA agnostic so we can just use one of the supported ones
  YAML::Node config;
  const std::vector<std::string> cmdLine = {
      SIMENG_SOURCE_DIR "/test/unit/data/stream-aarch64.elf"};

  simeng::kernel::Linux os;
  simeng::kernel::LinuxProcess proc_elf;
  simeng::kernel::LinuxProcess proc_hex;

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

// These test verifies the functionality of both the `createProcess()` and
// `getInitialStackPointer()` functions. All other functions for this class are
// syscalls and are tested in the Regression suite.
TEST_F(OSTest, processElf_stackPointer) {
  os.createProcess(proc_elf);
  EXPECT_EQ(os.getInitialStackPointer(), 1079830624);
  EXPECT_EQ(os.getInitialStackPointer(), proc_elf.getStackPointer());
}

TEST_F(OSTest, processHex_stackPointer) {
  os.createProcess(proc_hex);
  EXPECT_EQ(os.getInitialStackPointer(), 1074790240);
  EXPECT_EQ(os.getInitialStackPointer(), proc_hex.getStackPointer());
}

// createProcess
// getInitialStackPointer

}  // namespace simeng
