#include "gtest/gtest.h"
#include "simeng/OS/MemRegion.hh"
#include "simeng/OS/Process.hh"
#include "simeng/OS/SimOS.hh"
#include "simeng/OS/Vma.hh"
#include "simeng/version.hh"

using namespace simeng::OS;

namespace {
const std::string partialConfig =
    "{Core: {ISA: AArch64, Simulation-Mode: emulation, Clock-Frequency: 2.5, "
    "Timer-Frequency: 100, Micro-Operations: True, "
    "Vector-Length: 512, Streaming-Vector-Length: 512},"
    "Process-Image: {Heap-Size: 100000, Stack-Size: 100000, Mmap-Size: "
    "200000}, Memory-Hierarchy: {Cache-Line-Width: 64, DRAM: "
    "{Access-Latency: 1, Size: 500000}}, CPU-Info: "
    "{Generate-Special-Dir: False}}";

TEST(VirtMemTest, MmapSysCallNoAddressNoFile) {
  simeng::config::SimInfo::addToConfig(partialConfig);

  // Create simulation memory
  const size_t memorySize = simeng::config::SimInfo::getValue<size_t>(
      simeng::config::SimInfo::getConfig()["Memory-Hierarchy"]["DRAM"]["Size"]);
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(memorySize);
  // Create the instance of the OS
  simeng::span<char> defaultPrg = simeng::span<char>(
      reinterpret_cast<char*>(simeng::OS::hex_), sizeof(simeng::OS::hex_));
  simeng::OS::SimOS simOS = simeng::OS::SimOS(memory, defaultPrg);
  uint64_t procTID = 1;  // Initial process will always have TID = 1

  // Inject fake syscall into queue
  simOS.getSyscallHandler()->receiveSyscall({});

  uint64_t retVal = simOS.getSyscallHandler()->mmap(0, 4096, 0, 0, -1, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(procTID)->getMemRegion().getVMASize(), 1);

  VMA vma = simOS.getProcess(procTID)->getMemRegion().getVMAHead();
  ASSERT_NE(vma.vmSize_, 0);

  uint64_t mmapStart = simOS.getProcess(procTID)->getMemRegion().getMmapStart();
  ASSERT_EQ(vma.vmStart_, mmapStart);
  ASSERT_EQ(vma.vmEnd_, mmapStart + 4096);
  ASSERT_EQ(vma.vmSize_, 4096);
  ASSERT_EQ(vma.hasFile(), false);
}

TEST(VirtMemTest, MmapSysCallNoAddressPageFault) {
  simeng::config::SimInfo::addToConfig(partialConfig);

  // Create simulation memory
  const size_t memorySize = simeng::config::SimInfo::getValue<size_t>(
      simeng::config::SimInfo::getConfig()["Memory-Hierarchy"]["DRAM"]["Size"]);
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(memorySize);

  // Create the instance of the OS
  simeng::span<char> defaultPrg = simeng::span<char>(
      reinterpret_cast<char*>(simeng::OS::hex_), sizeof(simeng::OS::hex_));
  simeng::OS::SimOS simOS = simeng::OS::SimOS(memory, defaultPrg);
  uint64_t procTID = 1;  // Initial process will always have TID = 1

  // Inject fake syscall into queue
  simOS.getSyscallHandler()->receiveSyscall({});

  uint64_t retVal = simOS.getSyscallHandler()->mmap(0, 4096, 0, 0, -1, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(procTID)->getMemRegion().getVMASize(), 1);

  VMA vma = simOS.getProcess(procTID)->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma.vmSize_ != 0);

  uint64_t mmapStart = simOS.getProcess(procTID)->getMemRegion().getMmapStart();
  ASSERT_EQ(vma.vmStart_, mmapStart);
  ASSERT_EQ(vma.vmEnd_, mmapStart + 4096);
  ASSERT_EQ(vma.vmSize_, 4096);
  ASSERT_EQ(vma.hasFile(), false);

  uint64_t paddr = simOS.getProcess(procTID)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);
  simOS.handleVAddrTranslation(mmapStart, procTID);
  paddr = simOS.getProcess(procTID)->translate(mmapStart);
  ASSERT_NE(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  uint64_t paddrWOffset = simOS.getProcess(procTID)->translate(mmapStart + 20);
  ASSERT_EQ(paddrWOffset, paddr + 20);
}

TEST(VirtMemTest, MmapSysCallOnAddressAndPageFault) {
  simeng::config::SimInfo::addToConfig(partialConfig);

  // Create simulation memory
  const size_t memorySize = simeng::config::SimInfo::getValue<size_t>(
      simeng::config::SimInfo::getConfig()["Memory-Hierarchy"]["DRAM"]["Size"]);
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(memorySize);

  // Create the instance of the OS
  simeng::span<char> defaultPrg = simeng::span<char>(
      reinterpret_cast<char*>(simeng::OS::hex_), sizeof(simeng::OS::hex_));
  simeng::OS::SimOS simOS = simeng::OS::SimOS(memory, defaultPrg);
  uint64_t procTID = 1;  // Initial process will always have TID = 1
  uint64_t mmapStart = simOS.getProcess(procTID)->getMemRegion().getMmapStart();

  // Inject fake syscall into queue
  simOS.getSyscallHandler()->receiveSyscall({});

  uint64_t retVal =
      simOS.getSyscallHandler()->mmap(mmapStart + 4096, 4096, 0, 0, -1, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(procTID)->getMemRegion().getVMASize(), 1);

  VMA vma = simOS.getProcess(procTID)->getMemRegion().getVMAHead();
  ASSERT_NE(vma.vmSize_, 0);

  ASSERT_EQ(vma.vmStart_, mmapStart + 4096);
  ASSERT_EQ(vma.vmEnd_, mmapStart + 8192);
  ASSERT_EQ(vma.vmSize_, 4096);
  ASSERT_EQ(vma.hasFile(), false);

  uint64_t paddr = simOS.getProcess(procTID)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);
  simOS.handleVAddrTranslation(mmapStart + 4096, procTID);
  paddr = simOS.getProcess(procTID)->translate(mmapStart + 4096);
  ASSERT_NE(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  uint64_t paddrWOffset =
      simOS.getProcess(procTID)->translate(mmapStart + 4096 + 20);
  ASSERT_EQ(paddrWOffset, paddr + 20);
}

TEST(VirtMemTest, UnmapSyscall) {
  simeng::config::SimInfo::addToConfig(partialConfig);

  // Create simulation memory
  const size_t memorySize = simeng::config::SimInfo::getValue<size_t>(
      simeng::config::SimInfo::getConfig()["Memory-Hierarchy"]["DRAM"]["Size"]);
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(memorySize);
  // Create the instance of the OS
  simeng::span<char> defaultPrg = simeng::span<char>(
      reinterpret_cast<char*>(simeng::OS::hex_), sizeof(simeng::OS::hex_));
  simeng::OS::SimOS simOS = simeng::OS::SimOS(memory, defaultPrg);
  uint64_t procTID = 1;  // Initial process will always have TID = 1
  uint64_t mmapStart = simOS.getProcess(procTID)->getMemRegion().getMmapStart();

  // Inject fake syscall into queue
  simOS.getSyscallHandler()->receiveSyscall({});

  uint64_t retVal =
      simOS.getSyscallHandler()->mmap(mmapStart, 4096, 0, 0, -1, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(procTID)->getMemRegion().getVMASize(), 1);

  VMA vma = simOS.getProcess(procTID)->getMemRegion().getVMAHead();
  ASSERT_NE(vma.vmSize_, 0);

  ASSERT_EQ(vma.vmStart_, mmapStart);
  ASSERT_EQ(vma.vmEnd_, mmapStart + 4096);
  ASSERT_EQ(vma.vmSize_, 4096);
  ASSERT_EQ(vma.hasFile(), false);

  uint64_t paddr = simOS.getProcess(procTID)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  simOS.handleVAddrTranslation(mmapStart, procTID);
  paddr = simOS.getProcess(procTID)->translate(mmapStart);
  ASSERT_NE(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  retVal = simOS.getSyscallHandler()->munmap(mmapStart, 4096);
  ASSERT_EQ(retVal, 4096);

  paddr = simOS.getProcess(procTID)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  ASSERT_EQ(simOS.getProcess(procTID)->getMemRegion().getVMASize(), 0);

  vma = simOS.getProcess(procTID)->getMemRegion().getVMAHead();
  ASSERT_EQ(vma.vmSize_, 0);
  ASSERT_EQ(simOS.getProcess(procTID)->getMemRegion().getVMASize(), 0);
}

TEST(VirtMemTest, MmapSyscallWithFileNoOffset) {
  simeng::config::SimInfo::addToConfig(partialConfig);

  // Create simulation memory
  const size_t memorySize = simeng::config::SimInfo::getValue<size_t>(
      simeng::config::SimInfo::getConfig()["Memory-Hierarchy"]["DRAM"]["Size"]);
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(memorySize);

  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/longtext.txt";

  // Create the instance of the OS
  simeng::span<char> defaultPrg = simeng::span<char>(
      reinterpret_cast<char*>(simeng::OS::hex_), sizeof(simeng::OS::hex_));
  simeng::OS::SimOS simOS = simeng::OS::SimOS(memory, defaultPrg);
  uint64_t procTID = 1;  // Initial process will always have TID = 1
  uint64_t mmapStart = simOS.getProcess(procTID)->getMemRegion().getMmapStart();

  auto process = simOS.getProcess(procTID);
  int fd = process->fdArray_->allocateFDEntry(0, fpath.c_str(), O_RDWR, 0666);
  ASSERT_NE(fd, -1);

  // Inject fake syscall into queue
  simOS.getSyscallHandler()->receiveSyscall({});

  uint64_t retVal = simOS.getSyscallHandler()->mmap(mmapStart, 21, 0, 0, fd, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(procTID)->getMemRegion().getVMASize(), 1);

  VMA vma = simOS.getProcess(procTID)->getMemRegion().getVMAHead();
  ASSERT_NE(vma.vmSize_, 0);

  ASSERT_EQ(vma.vmStart_, mmapStart);
  ASSERT_EQ(vma.vmEnd_, mmapStart + 4096);
  ASSERT_EQ(vma.vmSize_, 4096);
  EXPECT_TRUE(vma.hasFile());
  ASSERT_EQ(vma.getFileSize(), 21);

  uint64_t paddr = simOS.getProcess(procTID)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  simOS.handleVAddrTranslation(mmapStart, procTID);
  paddr = simOS.getProcess(procTID)->translate(mmapStart);
  ASSERT_NE(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  auto data = memory->getUntimedData(paddr, vma.getFileSize());
  data.push_back('\0');

  std::string text = "111111111111111111111";
  ASSERT_EQ(text, std::string(data.data()));
}

TEST(VirtMemTest, MmapSyscallWithFileAndOffset) {
  simeng::config::SimInfo::addToConfig(partialConfig);

  // Create simulation memory
  const size_t memorySize = simeng::config::SimInfo::getValue<size_t>(
      simeng::config::SimInfo::getConfig()["Memory-Hierarchy"]["DRAM"]["Size"]);
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(memorySize);

  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/longtext.txt";

  // Create the instance of the OS
  simeng::span<char> defaultPrg = simeng::span<char>(
      reinterpret_cast<char*>(simeng::OS::hex_), sizeof(simeng::OS::hex_));
  simeng::OS::SimOS simOS = simeng::OS::SimOS(memory, defaultPrg);
  uint64_t procTID = 1;  // Initial process will always have TID = 1
  uint64_t mmapStart = simOS.getProcess(procTID)->getMemRegion().getMmapStart();

  auto process = simOS.getProcess(procTID);
  int fd = process->fdArray_->allocateFDEntry(0, fpath.c_str(), O_RDWR, 0666);
  ASSERT_NE(fd, -1);

  // Inject fake syscall into queue
  simOS.getSyscallHandler()->receiveSyscall({});

  uint64_t retVal =
      simOS.getSyscallHandler()->mmap(mmapStart, 4096, 0, 0, fd, 4096);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(procTID)->getMemRegion().getVMASize(), 1);

  VMA vma = simOS.getProcess(procTID)->getMemRegion().getVMAHead();
  ASSERT_NE(vma.vmSize_, 0);

  ASSERT_EQ(vma.vmStart_, mmapStart);
  ASSERT_EQ(vma.vmEnd_, mmapStart + 4096);
  ASSERT_EQ(vma.vmSize_, 4096);
  EXPECT_TRUE(vma.hasFile());
  ASSERT_EQ(vma.getFileSize(), 4096);

  uint64_t paddr = simOS.getProcess(procTID)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  simOS.handleVAddrTranslation(mmapStart, procTID);
  paddr = simOS.getProcess(procTID)->translate(mmapStart);
  ASSERT_NE(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  auto data = memory->getUntimedData(paddr, vma.getFileSize());
  data.push_back('\0');
  std::string text = "";
  for (int x = 0; x < 4096; x++) text += "2";
  ASSERT_EQ(text, std::string(data.data()));
}

TEST(VirtMemTest, MultiplePageFaultMmapSyscallWithFileAndOffset) {
  simeng::config::SimInfo::addToConfig(partialConfig);

  // Create simulation memory
  const size_t memorySize = simeng::config::SimInfo::getValue<size_t>(
      simeng::config::SimInfo::getConfig()["Memory-Hierarchy"]["DRAM"]["Size"]);
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(memorySize);

  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/longtext.txt";

  // Create the instance of the OS
  simeng::span<char> defaultPrg = simeng::span<char>(
      reinterpret_cast<char*>(simeng::OS::hex_), sizeof(simeng::OS::hex_));
  simeng::OS::SimOS simOS = simeng::OS::SimOS(memory, defaultPrg);
  uint64_t procTID = 1;  // Initial process will always have TID = 1
  uint64_t mmapStart = simOS.getProcess(procTID)->getMemRegion().getMmapStart();

  auto process = simOS.getProcess(procTID);
  int fd = process->fdArray_->allocateFDEntry(0, fpath.c_str(), O_RDWR, 0666);
  ASSERT_NE(fd, -1);

  // Inject fake syscall into queue
  simOS.getSyscallHandler()->receiveSyscall({});

  uint64_t retVal =
      simOS.getSyscallHandler()->mmap(mmapStart, 8192, 0, 0, fd, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(procTID)->getMemRegion().getVMASize(), 1);

  VMA vma = simOS.getProcess(procTID)->getMemRegion().getVMAHead();
  ASSERT_NE(vma.vmSize_, 0);

  ASSERT_EQ(vma.vmStart_, mmapStart);
  ASSERT_EQ(vma.vmEnd_, mmapStart + 8192);
  ASSERT_EQ(vma.vmSize_, 8192);
  EXPECT_TRUE(vma.hasFile());
  ASSERT_EQ(vma.getFileSize(), 8192);

  uint64_t paddr = simOS.getProcess(procTID)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  simOS.handleVAddrTranslation(mmapStart, procTID);
  paddr = simOS.getProcess(procTID)->translate(mmapStart);
  ASSERT_NE(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  auto data = memory->getUntimedData(paddr, 4096);
  data.push_back('\0');
  std::string text = "";
  for (int x = 0; x < 4096; x++) text += "1";
  ASSERT_EQ(text, std::string(data.data()));

  paddr = simOS.getProcess(procTID)->translate(mmapStart + 4096);
  ASSERT_EQ(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  simOS.handleVAddrTranslation(mmapStart + 4096, procTID);
  paddr = simOS.getProcess(procTID)->translate(mmapStart + 4096);
  ASSERT_NE(paddr, masks::faults::pagetable::FAULT |
                       masks::faults::pagetable::TRANSLATE);

  data = memory->getUntimedData(paddr, 4096 + 1);
  data.push_back('\0');

  text = "";
  for (int x = 0; x < 4096; x++) text += "2";
  ASSERT_EQ(text, std::string(data.data()));
}

}  // namespace
