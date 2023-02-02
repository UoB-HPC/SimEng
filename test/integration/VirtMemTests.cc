#include <filesystem>

#include "gtest/gtest.h"
#include "simeng/kernel/MemRegion.hh"
#include "simeng/kernel/Process.hh"
#include "simeng/kernel/SimOS.hh"
#include "simeng/kernel/Vma.hh"
#include "simeng/version.hh"

using namespace simeng::kernel;

namespace {

namespace env {
class VirtMemTestEnv : public ::testing::Environment {
 private:
  std::string fpath;

 public:
  ~VirtMemTestEnv() override {}

  // Override this to define how to set up the environment.
  // Create a file with size greater than 4096 to test offsets.
  // This needs to be done because offset has to be a multiple of pageSize,
  // other mmap will fail.
  void SetUp() override {
    std::string build_dir_path(SIMENG_BUILD_DIR);
    fpath = build_dir_path + "/test/integration/data/longtext.txt";

    std::ofstream fs(fpath);

    for (size_t i = 0; i < 4096; i++) {
      fs << 1;
    }
    for (size_t i = 0; i < 4096; i++) {
      fs << 2;
    }
    fs.close();
  }

  // Override this to define how to tear down the environment.
  // Delete the created longtext.txt file.
  void TearDown() override {
    if (!std::filesystem::remove(fpath)) {
      std::cerr << "Error occured while deleting longtext.txt file at path: "
                << fpath << std::endl;
    }
  }
};

testing::Environment* const env =
    testing::AddGlobalTestEnvironment(new VirtMemTestEnv);

}  // namespace env

TEST(VirtMemTest, MmapSysCallNoAddressNoFile) {
  Config::set(
      "{Core: {Simulation-Mode: emulation, Clock-Frequency: 2.5, "
      "Timer-Frequency: 100, Micro-Operations: True, "
      "Vector-Length: 512, Streaming-Vector-Length: 512}, Process-Image: "
      "{Heap-Size: 100000, Stack-Size: 100000}, CPU-Info: "
      "{Generate-Special-Dir: "
      "False}}");
  // Create global memory
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(300000);

  // Create the instance of the OS
  simeng::kernel::SimOS simOS =
      simeng::kernel::SimOS(DEFAULT_STR, {}, memory, true);

  uint64_t retVal = simOS.getSyscallHandler()->mmap(0, 4096, 0, 0, -1, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(0)->getMemRegion().getVMASize(), 1);

  VMA* vma = simOS.getProcess(0)->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma != NULL);

  uint64_t mmapStart = simOS.getProcess(0)->getMemRegion().getMmapStart();
  ASSERT_EQ(vma->vmStart_, mmapStart);
  ASSERT_EQ(vma->vmEnd_, mmapStart + 4096);
  ASSERT_EQ(vma->vmSize_, 4096);
  ASSERT_EQ(vma->hasFile(), false);
}

TEST(VirtMemTest, MmapSysCallNoAddressPageFault) {
  Config::set(
      "{Core: {Simulation-Mode: emulation, Clock-Frequency: 2.5, "
      "Timer-Frequency: 100, Micro-Operations: True, "
      "Vector-Length: 512, Streaming-Vector-Length: 512}, Process-Image: "
      "{Heap-Size: 100000, Stack-Size: 100000}, CPU-Info: "
      "{Generate-Special-Dir: "
      "False}}");
  // Create global memory
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(300000);

  // Create the instance of the OS
  simeng::kernel::SimOS simOS =
      simeng::kernel::SimOS(DEFAULT_STR, {}, memory, true);

  uint64_t retVal = simOS.getSyscallHandler()->mmap(0, 4096, 0, 0, -1, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(0)->getMemRegion().getVMASize(), 1);

  VMA* vma = simOS.getProcess(0)->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma != NULL);

  uint64_t mmapStart = simOS.getProcess(0)->getMemRegion().getMmapStart();
  ASSERT_EQ(vma->vmStart_, mmapStart);
  ASSERT_EQ(vma->vmEnd_, mmapStart + 4096);
  ASSERT_EQ(vma->vmSize_, 4096);
  ASSERT_EQ(vma->hasFile(), false);

  uint64_t paddr = simOS.getProcess(0)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);
  simOS.handleVAddrTranslation(mmapStart, 0);
  paddr = simOS.getProcess(0)->translate(mmapStart);
  ASSERT_NE(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  uint64_t paddrWOffset = simOS.getProcess(0)->translate(mmapStart + 20);
  ASSERT_EQ(paddrWOffset, paddr + 20);
}

TEST(VirtMemTest, MmapSysCallOnAddressAndPageFault) {
  Config::set(
      "{Core: {Simulation-Mode: emulation, Clock-Frequency: 2.5, "
      "Timer-Frequency: 100, Micro-Operations: True, "
      "Vector-Length: 512, Streaming-Vector-Length: 512}, Process-Image: "
      "{Heap-Size: 100000, Stack-Size: 100000}, CPU-Info: "
      "{Generate-Special-Dir: "
      "False}}");
  // Create global memory
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(300000);

  // Create the instance of the OS
  simeng::kernel::SimOS simOS =
      simeng::kernel::SimOS(DEFAULT_STR, {}, memory, true);
  uint64_t mmapStart = simOS.getProcess(0)->getMemRegion().getMmapStart();

  uint64_t retVal =
      simOS.getSyscallHandler()->mmap(mmapStart + 4096, 4096, 0, 0, -1, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(0)->getMemRegion().getVMASize(), 1);

  VMA* vma = simOS.getProcess(0)->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma != NULL);

  ASSERT_EQ(vma->vmStart_, mmapStart + 4096);
  ASSERT_EQ(vma->vmEnd_, mmapStart + 8192);
  ASSERT_EQ(vma->vmSize_, 4096);
  ASSERT_EQ(vma->hasFile(), false);

  uint64_t paddr = simOS.getProcess(0)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);
  simOS.handleVAddrTranslation(mmapStart + 4096, 0);
  paddr = simOS.getProcess(0)->translate(mmapStart + 4096);
  ASSERT_NE(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  uint64_t paddrWOffset = simOS.getProcess(0)->translate(mmapStart + 4096 + 20);
  ASSERT_EQ(paddrWOffset, paddr + 20);
}

TEST(VirtMemTest, UnmapSyscall) {
  Config::set(
      "{Core: {Simulation-Mode: emulation, Clock-Frequency: 2.5, "
      "Timer-Frequency: 100, Micro-Operations: True, "
      "Vector-Length: 512, Streaming-Vector-Length: 512}, Process-Image: "
      "{Heap-Size: 100000, Stack-Size: 100000}, CPU-Info: "
      "{Generate-Special-Dir: "
      "False}}");
  // Create global memory
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(300000);

  // Create the instance of the OS
  simeng::kernel::SimOS simOS =
      simeng::kernel::SimOS(DEFAULT_STR, {}, memory, true);
  uint64_t mmapStart = simOS.getProcess(0)->getMemRegion().getMmapStart();

  uint64_t retVal =
      simOS.getSyscallHandler()->mmap(mmapStart, 4096, 0, 0, -1, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(0)->getMemRegion().getVMASize(), 1);

  VMA* vma = simOS.getProcess(0)->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma != NULL);

  ASSERT_EQ(vma->vmStart_, mmapStart);
  ASSERT_EQ(vma->vmEnd_, mmapStart + 4096);
  ASSERT_EQ(vma->vmSize_, 4096);
  ASSERT_EQ(vma->hasFile(), false);

  uint64_t paddr = simOS.getProcess(0)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  simOS.handleVAddrTranslation(mmapStart, 0);
  paddr = simOS.getProcess(0)->translate(mmapStart);
  ASSERT_NE(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  retVal = simOS.getSyscallHandler()->munmap(mmapStart, 4096);
  ASSERT_EQ(retVal, 4096);

  paddr = simOS.getProcess(0)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  ASSERT_EQ(simOS.getProcess(0)->getMemRegion().getVMASize(), 0);

  vma = simOS.getProcess(0)->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma == NULL);
}

TEST(VirtMemTest, MmapSyscallWithFileNoOffset) {
  Config::set(
      "{Core: {Simulation-Mode: emulation, Clock-Frequency: 2.5, "
      "Timer-Frequency: 100, Micro-Operations: True, "
      "Vector-Length: 512, Streaming-Vector-Length: 512}, Process-Image: "
      "{Heap-Size: 100000, Stack-Size: 100000}, CPU-Info: "
      "{Generate-Special-Dir: "
      "False}}");
  // Create global memory
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(300000);

  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/unit/Data.txt";

  // Create the instance of the OS
  simeng::kernel::SimOS simOS =
      simeng::kernel::SimOS(DEFAULT_STR, {}, memory, true);
  uint64_t mmapStart = simOS.getProcess(0)->getMemRegion().getMmapStart();

  auto process = simOS.getProcess(0);
  int fd = process->fdArray_->allocateFDEntry(0, fpath.c_str(), O_RDWR, 0666);
  ASSERT_NE(fd, -1);

  uint64_t retVal = simOS.getSyscallHandler()->mmap(mmapStart, 21, 0, 0, fd, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(0)->getMemRegion().getVMASize(), 1);

  VMA* vma = simOS.getProcess(0)->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma != NULL);

  ASSERT_EQ(vma->vmStart_, mmapStart);
  ASSERT_EQ(vma->vmEnd_, mmapStart + 4096);
  ASSERT_EQ(vma->vmSize_, 4096);
  EXPECT_TRUE(vma->hasFile());
  ASSERT_EQ(vma->getFileSize(), 21);

  uint64_t paddr = simOS.getProcess(0)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  simOS.handleVAddrTranslation(mmapStart, 0);
  paddr = simOS.getProcess(0)->translate(mmapStart);
  ASSERT_NE(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  char* data = memory->getUntimedData(paddr, vma->getFileSize());
  std::string text = "FileDescArrayTestData";
  ASSERT_EQ(text, std::string(data));

  delete data;
}

TEST(VirtMemTest, MmapSyscallWithFileAndOffset) {
  Config::set(
      "{Core: {Simulation-Mode: emulation, Clock-Frequency: 2.5, "
      "Timer-Frequency: 100, Micro-Operations: True, "
      "Vector-Length: 512, Streaming-Vector-Length: 512}, Process-Image: "
      "{Heap-Size: 100000, Stack-Size: 100000}, CPU-Info: "
      "{Generate-Special-Dir: "
      "False}}");
  // Create global memory
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(300000);

  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/integration/data/longtext.txt";

  // Create the instance of the OS
  simeng::kernel::SimOS simOS =
      simeng::kernel::SimOS(DEFAULT_STR, {}, memory, true);
  uint64_t mmapStart = simOS.getProcess(0)->getMemRegion().getMmapStart();

  auto process = simOS.getProcess(0);
  int fd = process->fdArray_->allocateFDEntry(0, fpath.c_str(), O_RDWR, 0666);
  ASSERT_NE(fd, -1);

  uint64_t retVal =
      simOS.getSyscallHandler()->mmap(mmapStart, 4096, 0, 0, fd, 4096);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(0)->getMemRegion().getVMASize(), 1);

  VMA* vma = simOS.getProcess(0)->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma != NULL);

  ASSERT_EQ(vma->vmStart_, mmapStart);
  ASSERT_EQ(vma->vmEnd_, mmapStart + 4096);
  ASSERT_EQ(vma->vmSize_, 4096);
  EXPECT_TRUE(vma->hasFile());
  ASSERT_EQ(vma->getFileSize(), 4096);

  uint64_t paddr = simOS.getProcess(0)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  simOS.handleVAddrTranslation(mmapStart, 0);
  paddr = simOS.getProcess(0)->translate(mmapStart);
  ASSERT_NE(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  char* data = memory->getUntimedData(paddr, vma->getFileSize());
  std::string text = "";
  for (int x = 0; x < 4096; x++) text += "2";
  ASSERT_EQ(text, std::string(data));

  delete data;
}

TEST(VirtMemTest, MultiplePageFaultMmapSyscallWithFileAndOffset) {
  Config::set(
      "{Core: {Simulation-Mode: emulation, Clock-Frequency: 2.5, "
      "Timer-Frequency: 100, Micro-Operations: True, "
      "Vector-Length: 512, Streaming-Vector-Length: 512}, Process-Image: "
      "{Heap-Size: 100000, Stack-Size: 100000}, CPU-Info: "
      "{Generate-Special-Dir: "
      "False}}");
  // Create global memory
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(300000);

  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/integration/data/longtext.txt";

  // Create the instance of the OS
  simeng::kernel::SimOS simOS =
      simeng::kernel::SimOS(DEFAULT_STR, {}, memory, true);
  uint64_t mmapStart = simOS.getProcess(0)->getMemRegion().getMmapStart();

  auto process = simOS.getProcess(0);
  int fd = process->fdArray_->allocateFDEntry(0, fpath.c_str(), O_RDWR, 0666);
  ASSERT_NE(fd, -1);

  uint64_t retVal =
      simOS.getSyscallHandler()->mmap(mmapStart, 8192, 0, 0, fd, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess(0)->getMemRegion().getVMASize(), 1);

  VMA* vma = simOS.getProcess(0)->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma != NULL);

  ASSERT_EQ(vma->vmStart_, mmapStart);
  ASSERT_EQ(vma->vmEnd_, mmapStart + 8192);
  ASSERT_EQ(vma->vmSize_, 8192);
  EXPECT_TRUE(vma->hasFile());
  ASSERT_EQ(vma->getFileSize(), 8192);

  uint64_t paddr = simOS.getProcess(0)->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  simOS.handleVAddrTranslation(mmapStart, 0);
  paddr = simOS.getProcess(0)->translate(mmapStart);
  ASSERT_NE(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  char* data = memory->getUntimedData(paddr, 4096);
  std::string text = "";
  for (int x = 0; x < 4096; x++) text += "1";
  ASSERT_EQ(text, std::string(data));
  delete data;

  paddr = simOS.getProcess(0)->translate(mmapStart + 4096);
  ASSERT_EQ(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  simOS.handleVAddrTranslation(mmapStart + 4096, 0);
  paddr = simOS.getProcess(0)->translate(mmapStart + 4096);
  ASSERT_NE(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  data = memory->getUntimedData(paddr, 4096);
  text = "";
  for (int x = 0; x < 4096; x++) text += "2";
  ASSERT_EQ(text, std::string(data));
  delete data;
}

}  // namespace
