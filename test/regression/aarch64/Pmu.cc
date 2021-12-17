#include <cstring>
#include <fstream>

#include "AArch64RegressionTest.hh"

namespace {

using PMU = AArch64RegressionTest;

void createAttributeStructure(unsigned char* dest, uint32_t type, uint32_t size,
                              uint64_t config, uint64_t readFormat,
                              uint64_t eventConfig) {
  // Clear area of memory
  memset(dest, 0, 112);
  // Create perf_event_attr
  memcpy(dest, &type, 4);
  memcpy(dest + 4, &size, 4);
  memcpy(dest + 8, &config, 8);
  memcpy(dest + 32, &readFormat, 8);
  memcpy(dest + 40, &eventConfig, 8);
}

TEST_P(PMU, create_event) {
  // perf_event_open: test it returns a new fd
  initialHeapData_.resize(112);
  createAttributeStructure(initialHeapData_.data(), 4, 112, 0x11, 12, 97);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # perf_event_open(attr=&perf_event_attr, pid=0, cpu=-1, group_fd=-1, flags=0)
    mov x1, #0
    mov x2, #-1
    mov x3, #-1
    mov x4, #0
    mov x8, #241
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 3);

  // Ensure unsupported pid/cpu/flags are caught
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # perf_event_open(attr=&perf_event_attr, pid=-1, cpu=-1, group_fd=-1, flags=0)
    mov x1, #-1
    mov x2, #-1
    mov x3, #-1
    mov x4, #0
    mov x8, #241
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), -1);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # perf_event_open(attr=&perf_event_attr, pid=0, cpu=0, group_fd=-1, flags=0)
    mov x1, #0
    mov x2, #0
    mov x3, #-1
    mov x4, #0
    mov x8, #241
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), -1);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # perf_event_open(attr=&perf_event_attr, pid=0, cpu=-1, group_fd=-1, flags=1)
    mov x1, #0
    mov x2, #-1
    mov x3, #-1
    mov x4, #1
    mov x8, #241
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), -1);

  // Ensure unsupported read_format and eventConfig options are caught
  // All read_format options enabled
  createAttributeStructure(initialHeapData_.data(), 4, 112, 0x11, 15, 97);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # perf_event_open(attr=&perf_event_attr, pid=0, cpu=-1, group_fd=-1, flags=1)
    mov x1, #0
    mov x2, #-1
    mov x3, #-1
    mov x4, #1
    mov x8, #241
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), -1);
  // All event config options enabled
  createAttributeStructure(initialHeapData_.data(), 4, 112, 0x11, 12,
                           0x3FFFFFFFF);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # perf_event_open(attr=&perf_event_attr, pid=0, cpu=-1, group_fd=-1, flags=1)
    mov x1, #0
    mov x2, #-1
    mov x3, #-1
    mov x4, #1
    mov x8, #241
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), -1);
  // Monitoring for non user-space enabled
  createAttributeStructure(initialHeapData_.data(), 4, 112, 0x11, 12, 1);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # perf_event_open(attr=&perf_event_attr, pid=0, cpu=-1, group_fd=-1, flags=1)
    mov x1, #0
    mov x2, #-1
    mov x3, #-1
    mov x4, #1
    mov x8, #241
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), -1);
}

TEST_P(PMU, create_group) {
  // perf_event_open: test it returns a new fd
  initialHeapData_.resize(224);
  createAttributeStructure(initialHeapData_.data(), 4, 112, 0x11, 12, 97);
  createAttributeStructure(initialHeapData_.data() + 112, 4, 112, 0x8, 12, 97);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0 
    mov x8, 214
    svc #0

    add x9, x0, #112
    # perf_event_open(attr=&perf_event_attr, pid=0, cpu=-1, group_fd=-1, flags=0)
    mov x1, #0
    mov x2, #-1
    mov x3, #-1
    mov x4, #0
    mov x8, #241
    svc #0
    # perf_event_open(attr=&perf_event_attr, pid=0, cpu=-1, group_fd=x0, flags=0)
    mov x1, #0
    mov x2, #-1
    mov x3, x0
    mov x4, #0
    mov x8, #241
    mov x0, x9
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 4);
  // Ensure invalid groud_fd is caught
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0 
    mov x8, 214
    svc #0

    add x9, x0, #112
    # perf_event_open(attr=&perf_event_attr, pid=0, cpu=-1, group_fd=x0, flags=0)
    mov x1, #0
    mov x2, #-1
    mov x3, #1
    mov x4, #0
    mov x8, #241
    mov x0, x9
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), -1);
}

TEST_P(PMU, readInstructionCount) {
  initialHeapData_.resize(248);
  createAttributeStructure(initialHeapData_.data(), 4, 112, 0x11, 12, 97);
  createAttributeStructure(initialHeapData_.data() + 112, 4, 112, 0x8, 12, 97);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0 
    mov x8, 214
    svc #0

    mov x10, x0
    # perf_event_open(attr=&perf_event_attr, pid=0, cpu=-1, group_fd=-1, flags=0)
    mov x1, #0
    mov x2, #-1
    mov x3, #-1
    mov x4, #0
    mov x8, #241
    svc #0
    mov x9, x0
    add x0, x10, #112
    # perf_event_open(attr=&perf_event_attr, pid=0, cpu=-1, group_fd=-1, flags=0)
    mov x1, #0
    mov x2, #-1
    mov x3, #-1
    mov x4, #0
    mov x8, #241
    svc #0
    mov x9, x0

    # ioctl(fd=x9, request=PERF_EVENT_IOC_RESET)
    mov x2, #0
    mov x1, 0x2403
    mov x0, x9
    mov x8, #29
    svc #0

    mov x11, #0
    mov x12, #4095

    # ioctl(fd=x9, request=PERF_EVENT_IOC_ENABLE)
    mov x2, #0
    mov x1, 0x2400
    mov x0, x9
    mov x8, #29
    svc #0

    .loop:
    add x11, x11, #1
    subs x12, x12, #1
    b.ne .loop

    # ioctl(fd=x9, request=PERF_EVENT_IOC_DISABLE)
    mov x2, #0
    mov x1, 0x2401
    mov x0, x9
    mov x8, #29
    svc #0

    # read(fd=x9, buf=x10+112, count=24)
    mov x0, x9
    add x10, x10, #224
    mov x1, x10
    mov x2, #24
    mov x8, #63
    svc #0
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 224), 1);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 232), 12289);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 240), 1);
}

INSTANTIATE_TEST_SUITE_P(
    AArch64, PMU,
    ::testing::Values(std::make_tuple(EMULATION, YAML::Load("{}")),
                      std::make_tuple(INORDER, YAML::Load("{}")),
                      std::make_tuple(OUTOFORDER, YAML::Load("{}"))),
    paramToString);

}  // namespace
