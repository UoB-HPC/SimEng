#include <cstring>
#include <fstream>

#include "AArch64RegressionTest.hh"

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

// Test reading from and seeking through a file
TEST_P(Syscall, file_read) {
  const char filepath[] = SIMENG_AARCH64_TEST_ROOT "/data/input.txt";

  // Reserve 100 bytes for input read from file
  initialHeapData_.resize(100 + strlen(filepath) + 1);

  // Copy filepath to heap
  memcpy(initialHeapData_.data() + 100, filepath, strlen(filepath) + 1);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x20, x0

    # <input> = openat(AT_FDCWD, filepath, O_RDONLY, S_IRUSR)
    mov x0, -100
    add x1, x20, 100
    mov x2, 0x0000
    mov x3, 400
    mov x8, #56
    svc #0
    mov x21, x0

    # iovec = {{x0, 4}, {x0+8, 4}}
    mov x0, x20
    str x0, [sp, #-32]
    mov x1, 4
    str x1, [sp, #-24]
    add x0, x0, 8
    str x0, [sp, #-16]
    mov x1, 4
    str x1, [sp, #-8]

    # readv(fd=<input>, iov=iovec, iovcnt=2)
    mov x0, x21
    sub x1, sp, 32
    mov x2, #2
    mov x8, #65
    svc #0

    # lseek(fd=<input>, offset=12, whence=SEEK_SET)
    mov x0, x21
    mov x1, 12
    mov x2, 0
    mov x8, #62
    svc #0

    # iovec = {{x0+16, 8}, {x0 + 5, 2}}
    add x0, x20, 16
    str x0, [sp, #-32]
    mov x1, 8
    str x1, [sp, #-24]
    add x0, x20, 5
    str x0, [sp, #-16]
    mov x1, 2
    str x1, [sp, #-8]

    # readv(fd=<input>, iov=iovec, iovcnt=2)
    mov x0, x21
    sub x1, sp, 32
    mov x2, #2
    mov x8, #65
    svc #0

    # close(fd=<input>)
    mov x0, x21
    mov x8, #57
    svc #0
  )");

  // Check result of read operations
  const char reference[] = "ABCD\0UV\0EFGH\0\0\0\0MNOPQRST";
  char* data = processMemory_ + process_->getHeapStart();
  for (int i = 0; i < sizeof(reference); i++) {
    EXPECT_EQ(data[i], reference[i]) << "at index i=" << i << '\n';
  }
}

TEST_P(Syscall, file_write) {
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

TEST_P(Syscall, mprotect) {
  RUN_AARCH64(R"(
    mov x0, #47472
    mov x1, #4096
    mov x2, #1
    mov x8, #226
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0);
}

TEST_P(Syscall, newfstatat) {
  const char filepath[] = SIMENG_AARCH64_TEST_ROOT "/data/input.txt";
  // Reserve 128 bytes for statbuf
  initialHeapData_.resize(128 + strlen(filepath) + 1);
  // Copy filepath to heap
  memcpy(initialHeapData_.data() + 128, filepath, strlen(filepath) + 1);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x20, x0

    # newfstatat(dirfd=AT_FDCWD, pathname=/data/input.txt, statbuf, flags=0)
    mov x0, #-100
    add x1, x20, #128
    mov x2, x20
    mov x3, #0
    mov x8, #79
    svc #0
    mov x21, x0
  )");
  // Check fstatat returned 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(21), 0);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x20, x0

    # newfstatat(dirfd=AT_FDCWD, pathname=/data/input.txt, statbuf, flags=0)
    mov x0, #-100
    add x1, x20, #129
    mov x2, x20
    mov x3, #0
    mov x8, #79
    svc #0
    mov x21, x0
  )");
  // Check fstatat returned -1 (file not found)
  EXPECT_EQ(getGeneralRegister<uint64_t>(21), -1);
}

TEST_P(Syscall, ftruncate) {
  const char filepath[] = SIMENG_AARCH64_TEST_ROOT "/data/truncate-test.txt";

  // Copy filepath to heap
  initialHeapData_.resize(strlen(filepath) + 1);
  memcpy(initialHeapData_.data(), filepath, strlen(filepath) + 1);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x20, x0

    # <input> = openat(AT_FDCWD, filepath, O_WRONLY, S_IRUSR)
    mov x0, -100
    mov x1, x20
    mov x2, 0x0001
    mov x3, 400
    mov x8, #56
    svc #0
    mov x21, x0

    # ftruncate(fd, length) - increase length of file
    mov x0, x21
    mov x1, #100
    mov x8, #46
    svc #0
    mov x22, x0

    # ftruncate(fd, length) - decrease length of file
    mov x0, x21
    mov x1, #46
    mov x8, #46
    svc #0
    mov x23, x0

    # close(fd)
    mov x0, x21
    mov x8, #57
    svc #0
  )");
  // Check returned 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(22), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(23), 0);
}

INSTANTIATE_TEST_SUITE_P(AArch64, Syscall,
                         ::testing::Values(EMULATION, INORDER, OUTOFORDER),
                         coreTypeToString);

}  // namespace
