#include "gtest/gtest.h"
#include "simeng/kernel/SimOS.hh"

namespace {

// Test that we can create an SimOS object
TEST(OSTest, CreateSimOS) {
  // Set a config file with only the options required by the aarch64
  // architecture class to function
  Config::set(
      "{Core: {Simulation-Mode: emulation, Clock-Frequency: 2.5, "
      "Timer-Frequency: 100, Micro-Operations: True, "
      "Vector-Length: 512, Streaming-Vector-Length: 512}, Process-Image: "
      "{Heap-Size: 10000, Stack-Size: 10000}, CPU-Info: {Generate-Special-Dir: "
      "False}}");
  // Create global memory
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(25000);

  // Create the instance of the OS
  simeng::kernel::SimOS simOS_kernel =
      simeng::kernel::SimOS(1, nullptr, memory);

  // Check default process created
  auto proc = simOS_kernel.getProcess();
  EXPECT_GT(proc->getHeapStart(), 0);
  EXPECT_GT(proc->getMmapStart(), proc->getHeapStart());
  EXPECT_GT(proc->getStackStart(), proc->getMmapStart());
  EXPECT_EQ(proc->isValid(), true);

  // Check syscallHandler created
  EXPECT_TRUE(simOS_kernel.getSyscallHandler());
}

}  // namespace