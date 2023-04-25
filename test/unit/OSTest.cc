#include "gtest/gtest.h"
#include "simeng/OS/SimOS.hh"

namespace {

// Test that we can create an SimOS object
TEST(OSTest, CreateSimOS) {
  // Set a config file with only the options required by the aarch64
  // architecture class to function
  Config::set(
      "{Core: {ISA: AArch64, Simulation-Mode: emulation, Clock-Frequency: 2.5, "
      "Timer-Frequency: 100, Micro-Operations: True, "
      "Vector-Length: 512, Streaming-Vector-Length: 512}, Process-Image: "
      "{Heap-Size: 10000, Stack-Size: 10000, Mmap-Size: 20000}, "
      "Memory-Hierarchy: {Cache-Line-Width: 256, L1-Data: {Access-Latency: 1, "
      "Size: 100000}}, CPU-Info: {Generate-Special-Dir: False}}");
  // Create the simulation memory
  const size_t memorySize =
      Config::get()["Memory-Hierarchy"]["L1-Data"]["Size"].as<size_t>();
  const std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(memorySize);

  // Create the instance of the OS
  simeng::span<char> defaultPrg = simeng::span<char>(
      reinterpret_cast<char*>(simeng::OS::hex_), sizeof(simeng::OS::hex_));
  simeng::OS::SimOS OS = simeng::OS::SimOS(memory, defaultPrg);

  // Check default process created. Initial process TID = 1
  const std::shared_ptr<simeng::OS::Process> proc = OS.getProcess(1);
  EXPECT_GT(proc->getHeapStart(), 0);
  EXPECT_GT(proc->getMmapStart(), proc->getHeapStart());
  EXPECT_GT(proc->getStackStart(), proc->getMmapStart());
  EXPECT_EQ(proc->isValid(), true);
  // Check CPU context
  // PC is always 0 for processes assembled by SimEng
  EXPECT_EQ(proc->context_.pc, 0);
  EXPECT_GT(proc->context_.progByteLen, 0);
  EXPECT_GT(proc->context_.sp, 0);
  EXPECT_GT(proc->context_.regFile.size(), 0);
  // Check Initial Process' state
  EXPECT_EQ(proc->status_, simeng::OS::procStatus::waiting);

  // Check syscallHandler created
  EXPECT_TRUE(OS.getSyscallHandler());

  // Check terminateThread
  OS.terminateThread(1);
  EXPECT_EQ(OS.getNumProcesses(), 0);

  // Check terminateThreadGroup
  uint64_t procTid = OS.createProcess(defaultPrg);
  EXPECT_EQ(procTid, 2);
  OS.terminateThreadGroup(procTid);
  EXPECT_EQ(OS.getNumProcesses(), 0);
}

}  // namespace
