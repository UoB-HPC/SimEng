#include <stdlib.h>
#include <sys/syscall.h>

#include <cstring>
#include <fstream>
#include <string>

#include "AArch64RegressionTest.hh"

namespace {

using Syscall = AArch64RegressionTest;

/** The maximum size of a filesystem path. */
static const size_t LINUX_PATH_MAX = 4096;

TEST_P(Syscall, getrandom) {
  initialHeapData_.resize(24);
  memset(initialHeapData_.data(), -1, 16);

  RUN_AARCH64(R"(
      # Get heap address
      mov x0, 0
      mov x8, 214
      svc #0

      # store inital heap address
      mov x10, x0

      # Save 8 random bytes to the heap
      # getrandom(buf * = [a], buflen = 8, no flags)
      mov x1, #8
      mov x8, #278
      svc #0

      # Save another 8 random bytes to the heap
      # getrandom(buf * = [a], buflen = 8, no flags)
      add x0, x10, #8
      mov x1, #8
      mov x8, #278
      svc #0

    )");

  // Check getrandom returned 8 (8 bytes were requested)
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 8);

  int heapStart = getGeneralRegister<int64_t>(10);
  for (size_t i = 0; i < 8; i++) {
    printf("compare %x == %x\n", getMemoryValue<uint8_t>(heapStart + i),
           getMemoryValue<uint8_t>(heapStart + 8 + i));
  }

  // check that the retuned bytes arent all equal to -1.
  // heap was initialised to -1 so check bytes have changed
  bool allUnchanged = true;
  for (size_t i = 0; i < 16; i++) {
    if (getMemoryValue<uint8_t>(heapStart + i) != 0xFF) {
      allUnchanged = false;
      break;
    }
  }
  EXPECT_EQ(allUnchanged, false);

  // Check that the returned bytes from the two syscalls dont all match.
  // If they do then the returned bytes surely werent random
  bool allMatch = true;
  for (char i = 0; i < 8; i++) {
    if (getMemoryValue<uint8_t>(heapStart + i) !=
        getMemoryValue<uint8_t>(heapStart + 8 + i)) {
      allMatch = false;
      break;
    }
  }

  EXPECT_EQ(allMatch, false);
}

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

TEST_P(Syscall, faccessat) {
  const char filepath[] = "./tempFile.txt";
  initialHeapData_.resize(strlen(filepath) + 1);
  // Copy filepath to heap
  memcpy(initialHeapData_.data(), filepath, strlen(filepath) + 1);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, #0
    mov x8, 214
    svc #0
    mov x20, x0

    # Create a new file to access and close immediately
    # <tempfile> = openat(AT_FDCWD, filepath,
    #                     O_CREAT | O_TRUNC | O_WRONLY,
    #                     S_IRUSR)
    mov x0, -100
    mov x1, x20 
    mov x2, 0x0241
    mov x3, 400
    mov x8, #56
    svc #0
    mov x21, x0

    # close(fd=<input>)
    mov x0, x21
    mov x8, #57
    svc #0


    # faccessat(AT_FDCWD, filepath, F_OK, 0) = 0
    mov x0, #-100
    mov x1, x20
    mov x2, #0
    mov x3, #0
    mov x8, #48
    svc #0
    mov x21, x0

    # faccessat(AT_FDCWD, filepath, R_OK, 0) = 0
    mov x0, #-100
    mov x1, x20
    mov x2, #0x04
    mov x3, #0
    mov x8, #48
    svc #0
    mov x22, x0

    # faccessat(AT_FDCWD, filepath, W_OK, 0) = 0
    mov x0, #-100
    mov x1, x20
    mov x2, #0x02
    mov x3, #0
    mov x8, #48
    svc #0
    mov x23, x0

    # faccessat(AT_FDCWD, filepath, X_OK, 0) = -1
    # File targeted isn't executable
    mov x0, #-100
    mov x1, x20
    mov x2, #0x01
    mov x3, #0
    mov x8, #48
    svc #0
    mov x24, x0

    # faccessat(AT_FDCWD, wrongFilepath, F_OK, 0) = -1
    mov x0, #-100
    add x1, x20, #4
    mov x2, #0
    mov x3, #0
    mov x8, #48
    svc #0
    mov x25, x0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(21), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(22), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(23), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(24), -1);
  EXPECT_EQ(getGeneralRegister<int64_t>(25), -1);
  // Delete output file after running test
  unlink(filepath);

  char abs_filepath[LINUX_PATH_MAX];
  realpath(SIMENG_AARCH64_TEST_ROOT "/data/input.txt", abs_filepath);
  initialHeapData_.resize(strlen(abs_filepath) + 1);
  // Copy abs_filepath to heap
  memcpy(initialHeapData_.data(), abs_filepath, strlen(abs_filepath) + 1);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, #0
    mov x8, 214
    svc #0
    mov x20, x0

    # faccessat(-5, fullFilePath, F_OK, 0) = 0
    # If an absolute filepath is referenced, dirfd is ignored
    mov x0, #-5
    mov x1, x20
    mov x2, #0
    mov x3, #0
    mov x8, #48
    svc #0
    mov x26, x0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(26), 0);

  // Check syscall works using dirfd instead of AT_FDCWD
  const char file[] = "input.txt\0";
  char dirPath[LINUX_PATH_MAX];
  realpath(SIMENG_AARCH64_TEST_ROOT "/data/\0", dirPath);

  initialHeapData_.resize(strlen(dirPath) + strlen(file) + 2);
  // Copy dirPath to heap
  memcpy(initialHeapData_.data(), file, strlen(file) + 1);
  memcpy(initialHeapData_.data() + strlen(file) + 1, dirPath,
         strlen(dirPath) + 1);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, #0
    mov x8, 214
    svc #0
    mov x20, x0

    # Need to open the directory
    # dfd = openat(AT_FDCWD, dirPath, O_RDONLY)
    # Flags = 0x0
    mov x0, -100
    add x1, x20, #10
    mov x2, #0
    mov x8, #56
    svc #0
    mov x21, x0

    # faccessat(dfd, fullFilePath, F_OK, 0) = 0
    # If an absolute filepath is referenced, dirfd is ignored
    mov x0, x21
    mov x1, x20
    mov x2, #0
    mov x3, #0
    mov x8, #48
    svc #0
    mov x27, x0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(27), 0);
}

TEST_P(Syscall, getdents64) {
  const char filepath[] = SIMENG_AARCH64_TEST_ROOT "/data/\0";

  // Reserve 32768 bytes for buffer
  initialHeapData_.resize(32768 + strlen(filepath) + 1);

  // Copy filepath to heap
  memcpy(initialHeapData_.data() + 32768, filepath, strlen(filepath) + 1);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x20, x0

    # Need to open the directory
    # dfd = openat(AT_FDCWD, filepath, O_RDONLY)
    # Flags = 0x0
    mov x0, -100
    add x1, x20, 32768
    mov x2, #0
    mov x8, #56
    svc #0
    mov x21, x0

    # getdents64(dfd, bufptr, count)
    mov x0, x21
    mov x1, x20
    mov x2, #32768
    mov x8, #61
    svc #0
    mov x22, x0
  )");
  // Return value verified on system that utilises the actual getdents64 syscall
  EXPECT_EQ(getGeneralRegister<int64_t>(22), 120);
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

TEST_P(Syscall, mmap) {
  // Test for 3 consecutive allocations
  RUN_AARCH64(R"(
    # mmap(addr=NULL, length=65536, prot=3, flags=34, fd=-1, offset=0)
    mov x0, #0
    mov x1, #65536
    mov x2, #3
    mov x3, #34
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0
    mov x9, x0

    # mmap(addr=NULL, length=1024, prot=3, flags=34, fd=-1, offset=0)
    mov x0, #0
    mov x1, #1024
    mov x2, #3
    mov x3, #34
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0
    mov x10, x0

    # mmap(addr=NULL, length=16384, prot=3, flags=34, fd=-1, offset=0)
    mov x0, #0
    mov x1, #16384
    mov x2, #3
    mov x3, #34
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0
    mov x11, x0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), process_->getMmapStart());
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), process_->getMmapStart() + 65536);
  EXPECT_EQ(getGeneralRegister<uint64_t>(11), process_->getMmapStart() + 69632);

  // Test for mmap allocation between two previous allocations
  RUN_AARCH64(R"(
    # Setup 3 contiguous allocations
    # mmap(addr=NULL, length=1024, prot=3, flags=34, fd=-1, offset=0)
    mov x0, #0
    mov x1, #1024
    mov x2, #3
    mov x3, #34
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0
    mov x9, x0

    # mmap(addr=NULL, length=12288, prot=3, flags=34, fd=-1, offset=0)
    mov x0, #0
    mov x1, #12288
    mov x2, #3
    mov x3, #34
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0
    mov x10, x0

    # mmap(addr=NULL, length=1024, prot=3, flags=34, fd=-1, offset=0)
    mov x0, #0
    mov x1, #1024
    mov x2, #3
    mov x3, #34
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0
    mov x11, x0

    # unmap second allocation to create an empty space between allocations
    # munmap(addr=x10, length=12288, prot=3, flags=34, fd=-1, offset=0)
    mov x0, x10
    mov x1, #12288
    mov x8, #215
    svc #0
    mov x12, x0

    # Allocate a region larger than the new empty space
    # mmap(addr=NULL, length=16384, prot=3, flags=34, fd=-1, offset=0)
    mov x0, #0
    mov x1, #16384
    mov x2, #3
    mov x3, #34
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0
    mov x13, x0

    # Two allocations whose combined length equals the new empty space
    # mmap(addr=NULL, length=4096, prot=3, flags=34, fd=-1, offset=0)
    mov x0, #0
    mov x1, #4096
    mov x2, #3
    mov x3, #34
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0
    mov x14, x0

    # mmap(addr=NULL, length=8192, prot=3, flags=34, fd=-1, offset=0)
    mov x0, #0
    mov x1, #8192
    mov x2, #3
    mov x3, #34
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0
    mov x15, x0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), process_->getMmapStart());
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), process_->getMmapStart() + 4096);
  EXPECT_EQ(getGeneralRegister<uint64_t>(11), process_->getMmapStart() + 16384);
  EXPECT_EQ(getGeneralRegister<uint64_t>(12), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(13), process_->getMmapStart() + 20480);
  EXPECT_EQ(getGeneralRegister<uint64_t>(14), process_->getMmapStart() + 4096);
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), process_->getMmapStart() + 8192);
}

TEST_P(Syscall, munmap) {
  // Test that no errors are given during expected usage
  RUN_AARCH64(R"(
    # mmap(addr=NULL, length=65536, prot=3, flags=34, fd=-1, offset=0)
    mov x0, #0
    mov x1, #65536
    mov x2, #3
    mov x3, #34
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0
    mov x9, x0

    # munmap(addr=mmapStart_, length=65536, prot=3, flags=34, fd=-1, offset=0)
    mov x0, x9
    mov x1, #65536
    mov x8, #215
    svc #0
    mov x10, x0

    # munmap(addr=mmapStart_, length=65536, prot=3, flags=34, fd=-1, offset=0)
    mov x0, x9
    mov x1, #65536
    mov x8, #215
    svc #0
    mov x11, x0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), process_->getMmapStart());
  EXPECT_EQ(getGeneralRegister<int64_t>(10), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(11), 0);

  // Test that EINVAL error types trigger
  RUN_AARCH64(R"(
    # mmap(addr=NULL, length=1024, prot=3, flags=34, fd=-1, offset=0)
    mov x0, #0
    mov x1, #1024
    mov x2, #3
    mov x3, #34
    mov x4, #-1
    mov x5, #0
    mov x8, #222
    svc #0
    mov x9, x0

    # munmap(addr=mmapStart_, length=65536, prot=3, flags=34, fd=-1, offset=0)
    mov x0, x9
    mov x1, #65536
    mov x8, #215
    svc #0
    mov x10, x0

    # munmap(addr=mmapStart_, length=65536, prot=3, flags=34, fd=-1, offset=0)
    add x9, x9, #1024
    mov x0, x9
    mov x1, #65536
    mov x8, #215
    svc #0
    mov x11, x0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), process_->getMmapStart() + 1024);
  EXPECT_EQ(getGeneralRegister<int64_t>(10), -1);
  EXPECT_EQ(getGeneralRegister<int64_t>(11), -1);
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
  // Check mprotect returns placeholder value as currently not implemented
  RUN_AARCH64(R"(
    # mprotect(addr=47472, len=4096, prot=1) = 0
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

    # newfstatat(dirfd=AT_FDCWD, filepath, statbuf, flags=0)
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

    # newfstatat(dirfd=AT_FDCWD, wrongFilePath, statbuf, flags=0)
    mov x0, #-100
    add x1, x20, #130
    mov x2, x20
    mov x3, #0
    mov x8, #79
    svc #0
    mov x21, x0
  )");
  // Check fstatat returned -1 (file not found)
  EXPECT_EQ(getGeneralRegister<uint64_t>(21), -1);

  // Check syscall works using dirfd instead of AT_FDCWD
  const char file[] = "input.txt\0";
  char dirPath[LINUX_PATH_MAX];
  realpath(SIMENG_AARCH64_TEST_ROOT "/data/\0", dirPath);

  initialHeapData_.resize(128 + strlen(dirPath) + strlen(file) + 2);
  // Copy dirPath to heap
  memcpy(initialHeapData_.data() + 128, file, strlen(file) + 1);
  memcpy(initialHeapData_.data() + 128 + strlen(file) + 1, dirPath,
         strlen(dirPath) + 1);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, #0
    mov x8, 214
    svc #0
    mov x20, x0

    # Need to open the directory
    # dfd = openat(AT_FDCWD, dirPath, O_RDONLY)
    # Flags = 0x0
    mov x0, -100
    add x1, x20, #138
    mov x2, #0
    mov x8, #56
    svc #0
    mov x21, x0

    # newfstatat(dfd, file, statbuf, flags=0)
    mov x0, x21
    add x1, x20, #128
    mov x2, x20
    mov x3, #0
    mov x8, #79
    svc #0
    mov x21, x0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(27), 0);
}

TEST_P(Syscall, getrusage) {
  // Reserve 128 bytes for usage
  initialHeapData_.resize(128);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x20, x0

    # getrusage(who = RUSAGE_SELF, usage)
    mov x0, #0
    mov x1, x20
    mov x8, #165
    svc #0
    mov x21, x0

    # getrusage(who = RUSAGE_CHILDREN, usage)
    mov x0, #-1
    mov x1, x20
    mov x8, #165
    svc #0
    mov x22, x0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(21), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(22), 0);

  // MacOS doesn't support the final enum RUSAGE_THREAD
#ifndef __MACH__
  // Reserve 128 bytes for usage
  initialHeapData_.resize(128);
  RUN_AARCH64(R"(
      # Get heap address
      mov x0, 0
      mov x8, 214
      svc #0
      mov x20, x0

      # getrusage(who = RUSAGE_THREAD, usage)
      mov x0, #1
      mov x1, x20
      mov x8, #165
      svc #0
      mov x21, x0
    )");
  EXPECT_EQ(getGeneralRegister<int64_t>(21), 0);
#endif
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

INSTANTIATE_TEST_SUITE_P(
    AArch64, Syscall,
    ::testing::Values(std::make_tuple(EMULATION, YAML::Load("{}")),
                      std::make_tuple(INORDER, YAML::Load("{}")),
                      std::make_tuple(OUTOFORDER, YAML::Load("{}"))),
    paramToString);

}  // namespace
