#include "AArch64RegressionTest.hh"

#include <cstring>
#include <fstream>

namespace {

using Syscall = AArch64RegressionTest;

TEST_P(Syscall, ioctl) {
  // TIOCGWINSZ: test it returns zero and sets the output to anything
  initialHeapData_.resize(8);
  memset(initialHeapData_.data(), -1, 8);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # ioctl(fd=1, request=0x5413, argp=x0)
    mov x2, x0
    mov x1, 0x5413
    mov x0, #1
    mov x8, #29
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 0);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 0), -1);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 2), -1);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 4), -1);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 6), -1);
}

TEST_P(Syscall, fileio) {
  const char str[] = "Hello, World!\n";
  const char filepath[] = "./simeng-fileio-test.txt";

  // Delete output file before running test
  unlink(filepath);

  // Copy string and filepath to heap
  initialHeapData_.resize(strlen(str) + strlen(filepath) + 1);
  memcpy(initialHeapData_.data(), str, strlen(str));
  memcpy(initialHeapData_.data() + strlen(str), filepath, strlen(filepath) + 1);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x20, x0

    # <tempfile> = openat(AT_FDCWD, filepath,
    #                     O_CREAT | O_TRUNC | O_WRONLY,
    #                     S_IRUSR)
    mov x0, -100
    add x1, x20, 14
    mov x2, 0x0241
    mov x3, 400
    mov x8, #56
    svc #0
    mov x21, x0

    # iovec = {{x0, 10}, {x0+10, 4}}
    mov x0, x20
    str x0, [sp, #-32]
    mov x1, 10
    str x1, [sp, #-24]
    add x0, x0, 10
    str x0, [sp, #-16]
    mov x1, 4
    str x1, [sp, #-8]

    # writev(fd=<tempfile>, iov=iovec, iovcnt=2)
    mov x0, x21
    sub x1, sp, 32
    mov x2, #2
    mov x8, #66
    svc #0

    # close(fd=<tempfile>)
    mov x0, x21
    mov x8, #57
    svc #0
  )");

  // Check file contents
  char outdata[15];
  std::ifstream outfile(filepath);
  ASSERT_TRUE(outfile.good());
  outfile.read(outdata, 15);
  EXPECT_TRUE(outfile.eof());
  EXPECT_EQ(strncmp(str, outdata, 14), 0);
}

TEST_P(Syscall, filenotfound) {
  // Copy filepath to heap
  const char filepath[] = "./nonexistent-file";
  initialHeapData_.resize(strlen(filepath) + 1);
  memcpy(initialHeapData_.data(), filepath, strlen(filepath) + 1);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # <tempfile> = openat(AT_FDCWD, filepath, O_RDONLY, 0)
    mov x1, x0
    mov x0, -100
    mov x2, 0
    mov x3, 0
    mov x8, #56
    svc #0
  )");

  // Check return value is -1
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), -1);
}

TEST_P(Syscall, stdout) {
  const char str[] = "Hello, World!\n";
  for (char c : str) {
    initialHeapData_.push_back(c);
  }
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # iovec = {{x0, 10}, {x0+10, 4}}
    str x0, [sp, #-32]
    mov x1, 10
    str x1, [sp, #-24]
    add x0, x0, 10
    str x0, [sp, #-16]
    mov x1, 4
    str x1, [sp, #-8]

    # writev(fd=1, iov=iovec, iovcnt=2)
    mov x0, #1
    sub x1, sp, 32
    mov x2, #2
    mov x8, #66
    svc #0
  )");
  EXPECT_EQ(stdout_.substr(0, sizeof(str) - 1), str);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), sizeof(str) - 1);
}

INSTANTIATE_TEST_SUITE_P(AArch64, Syscall,
                         ::testing::Values(EMULATION, INORDER, OUTOFORDER),
                         coreTypeToString);

}  // namespace
