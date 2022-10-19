#include <dirent.h>
#include <fcntl.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

#include "RISCVRegressionTest.hh"

namespace {

using Syscall = RISCVRegressionTest;

/** The maximum size of a filesystem path. */
static const size_t LINUX_PATH_MAX = 4096;

TEST_P(Syscall, getrandom) {
  initialHeapData_.resize(24);
  memset(initialHeapData_.data(), -1, 16);

  RUN_RISCV(R"(
      # Get heap address
      li a0, 0
      li a7, 214
      ecall

      # store inital heap address
      mv t0, a0

      # Save 8 random bytes to the heap
      # getrandom(buf * = [a], buflen = 8, no flags)
      li a1, 8
      li a7, 278
      ecall

      # Save another 8 random bytes to the heap
      # getrandom(buf * = [a], buflen = 8, no flags)
      addi a0, t0, 8
      li a1, 8
      li a7, 278
      ecall
    )");

  // Check getrandom returned 8 (8 bytes were requested)
  EXPECT_EQ(getGeneralRegister<int64_t>(10), 8);

  int heapStart = getGeneralRegister<int64_t>(5);
  for (size_t i = 0; i < 8; i++) {
    printf("compare %x == %x\n", getMemoryValue<uint8_t>(heapStart + i),
           getMemoryValue<uint8_t>(heapStart + 8 + i));
  }

  // check that the returned bytes aren't all equal to -1.
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
  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall

    # ioctl(fd=1, request=0x5413, argp=a0)
    mv a2, a0
    li a1, 0x5413
    li a0, 1
    li a7, 29
    ecall
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

  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # Create a new file to access and close immediately
    # <tempfile> = openat(AT_FDCWD, filepath,
    #                     O_CREAT | O_TRUNC | O_WRONLY,
    #                     S_IRUSR)
    li a0, -100
    mv a1, t0
    li a2, 0x0241
    li a3, 400
    li a7, 56
    ecall
    mv t1, a0

    # close(fd=<input>)
    mv a0, t1
    li a7, 57
    ecall

    # faccessat(AT_FDCWD, filepath, F_OK, 0) = 0
    li a0, -100
    mv a1, t0
    li a2, 0
    li a3, 0
    li a7, 48
    ecall
    mv t1, a0

    # faccessat(AT_FDCWD, filepath, R_OK, 0) = 0
    li a0, -100
    mv a1, t0
    li a2, 0x04
    li a3, 0
    li a7, 48
    ecall
    mv t2, a0

    # faccessat(AT_FDCWD, filepath, W_OK, 0) = 0
    li a0, -100
    mv a1, t0
    li a2, 0x02
    li a3, 0
    li a7, 48
    ecall
    mv t3, a0

    # faccessat(AT_FDCWD, filepath, X_OK, 0) = -1
    # File targeted isn't executable
    li a0, -100
    mv a1, t0
    li a2, 0x01
    li a3, 0
    li a7, 48
    ecall
    mv t4, a0

    # faccessat(AT_FDCWD, wrongFilepath, F_OK, 0) = -1
    li a0, -100
    addi a1, t0, 4
    li a2, 0
    li a3, 0
    li a7, 48
    ecall
    mv t5, a0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(28), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(29), -1);
  EXPECT_EQ(getGeneralRegister<int64_t>(30), -1);
  // Delete output file after running test
  unlink(filepath);

  char abs_filepath[LINUX_PATH_MAX];
  realpath(SIMENG_RISCV_TEST_ROOT "/data/input.txt", abs_filepath);
  initialHeapData_.resize(strlen(abs_filepath) + 1);
  // Copy abs_filepath to heap
  memcpy(initialHeapData_.data(), abs_filepath, strlen(abs_filepath) + 1);
  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # faccessat(-5, fullFilePath, F_OK, 0) = 0
    # If an absolute filepath is referenced, dirfd is ignored
    li a0, -5
    mv a1, t0
    li a2, 0
    li a3, 0
    li a7, 48
    ecall
    mv t6, a0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(30), 0);

  // Check syscall works using dirfd instead of AT_FDCWD
  const char file[] = "input.txt\0";
  char dirPath[LINUX_PATH_MAX];
  realpath(SIMENG_RISCV_TEST_ROOT "/data/\0", dirPath);

  initialHeapData_.resize(strlen(dirPath) + strlen(file) + 2);
  // Copy dirPath to heap
  memcpy(initialHeapData_.data(), file, strlen(file) + 1);
  memcpy(initialHeapData_.data() + strlen(file) + 1, dirPath,
         strlen(dirPath) + 1);
  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # Need to open the directory
    # dfd = openat(AT_FDCWD, dirPath, O_RDONLY)
    # Flags = 0x0
    li a0, -100
    addi a1, t0, 10
    li a2, 0
    li a7, 56
    ecall
    mv t1, a0

    # faccessat(dfd, fullFilePath, F_OK, 0) = 0
    # If an absolute filepath is referenced, dirfd is ignored
    mv a0, t1
    mv a1, t0
    li a2, 0
    li a3, 0
    li a7, 48
    ecall
    mv t2, a0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(7), 0);
}

TEST_P(Syscall, getdents64) {
  const char filepath[] = SIMENG_RISCV_TEST_ROOT "/data/\0";

  // Reserve 32768 bytes for buffer
  initialHeapData_.resize(32768 + strlen(filepath) + 1);

  // Copy filepath to heap
  memcpy(initialHeapData_.data() + 32768, filepath, strlen(filepath) + 1);
  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # Need to open the directory
    # dfd = openat(AT_FDCWD, filepath, O_RDONLY)
    # Flags = 0x0
    li a0, -100
    li t3, 32768
    add a1, t0, t3
    li a2, 0
    li a7, 56
    ecall
    mv t1, a0

    # getdents64(dfd, bufptr, count)
    mv a0, t1
    mv a1, t0
    li a2, 32768
    li a7, 61
    ecall
    mv t2, a0
  )");
  // Return value verified on system that utilises the actual getdents64 syscall
  EXPECT_EQ(getGeneralRegister<int64_t>(7), 120);
}

// Test reading from and seeking through a file
TEST_P(Syscall, file_read) {
  const char filepath[] = SIMENG_RISCV_TEST_ROOT "/data/input.txt";

  // Reserve 100 bytes for input read from file
  initialHeapData_.resize(100 + strlen(filepath) + 1);

  // Copy filepath to heap
  memcpy(initialHeapData_.data() + 100, filepath, strlen(filepath) + 1);

  RUN_RISCV(R"(
    # load temporary for subtracts
    li t4, 32

    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # <input> = openat(AT_FDCWD, filepath, O_RDONLY, S_IRUSR)
    li a0, -100
    addi a1, t0, 100
    li a2, 0x0000
    li a3, 400
    li a7, 56
    ecall
    mv t1, a0

    # iovec = {{a0, 4}, {a0+8, 4}}
    mv a0, t0
    sd a0, -32(sp)
    li a1, 4
    sd a1, -24(sp)
    addi a0, a0, 8
    sd a0, -16(sp)
    li a1, 4
    sd a1, -8(sp)

    # readv(fd=<input>, iov=iovec, iovcnt=2)
    mv a0, t1
    sub a1, sp, t4
    li a2, 2
    li a7, 65
    ecall

    # lseek(fd=<input>, offset=12, whence=SEEK_SET)
    mv a0, t1
    li a1, 12
    li a2, 0
    li a7, 62
    ecall

    # iovec = {{a0+16, 8}, {a0 + 5, 2}}
    addi a0, t0, 16
    sd a0, -32(sp)
    li a1, 8
    sd a1, -24(sp)
    addi a0, t0, 5
    sd a0, -16(sp)
    li a1, 2
    sd a1, -8(sp)

    # readv(fd=<input>, iov=iovec, iovcnt=2)
    mv a0, t1
    sub a1, sp, t4
    li a2, 2
    li a7, 65
    ecall

    # close(fd=<input>)
    mv a0, t1
    li a7, 57
    ecall
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

  RUN_RISCV(R"(
    # load temporary for subtracts
    li t6, 32

    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # <tempfile> = openat(AT_FDCWD, filepath,
    #                     O_CREAT | O_TRUNC | O_WRONLY,
    #                     S_IRUSR)
    li a0, -100
    add a1, t0, 14
    li a2, 0x0241
    li a3, 400
    li a7, 56
    ecall
    mv t1, a0

    # iovec = {{a0, 10}, {a0+10, 4}}
    mv a0, t0
    sd a0, -32(sp)
    li a1, 10
    sd a1, -24(sp)
    addi a0, a0, 10
    sd a0, -16(sp)
    li a1, 4
    sd a1, -8(sp)

    # writev(fd=<tempfile>, iov=iovec, iovcnt=2)
    mv a0, t1
    sub a1, sp, t6
    li a2, 2
    li a7, 66
    ecall

    # close(fd=<tempfile>)
    mv a0, t1
    li a7, 57
    ecall
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

  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall

    # <tempfile> = openat(AT_FDCWD, filepath, O_RDONLY, 0)
    mv a1, a0
    li a0, -100
    li a2, 0
    li a3, 0
    li a7, 56
    ecall
  )");

  // Check return value is -1
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), -1);
}

TEST_P(Syscall, mmap) {
  // Test for 3 consecutive allocations
  RUN_RISCV(R"(
    # mmap(addr=NULL, length=65536, prot=3, flags=34, fd=-1, offset=0)
    li a0, 0
    li a1, 65536
    li a2, 3
    li a3, 34
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    mv t0, a0

    # mmap(addr=NULL, length=1024, prot=3, flags=34, fd=-1, offset=0)
    li a0, 0
    li a1, 1024
    li a2, 3
    li a3, 34
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    mv t1, a0

    # mmap(addr=NULL, length=16384, prot=3, flags=34, fd=-1, offset=0)
    li a0, 0
    li a1, 16384
    li a2, 3
    li a3, 34
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    mv t2, a0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), process_->getMmapStart());
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), process_->getMmapStart() + 65536);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), process_->getMmapStart() + 69632);

  // Test for mmap allocation between two previous allocations
  RUN_RISCV(R"(
    # Setup 3 contiguous allocations
    # mmap(addr=NULL, length=1024, prot=3, flags=34, fd=-1, offset=0)
    li a0, 0
    li a1, 1024
    li a2, 3
    li a3, 34
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    mv t0, a0

    # mmap(addr=NULL, length=12288, prot=3, flags=34, fd=-1, offset=0)
    li a0, 0
    li a1, 12288
    li a2, 3
    li a3, 34
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    mv t1, a0

    # mmap(addr=NULL, length=1024, prot=3, flags=34, fd=-1, offset=0)
    li a0, 0
    li a1, 1024
    li a2, 3
    li a3, 34
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    mv t2, a0

    # unmap second allocation to create an empty space between allocations
    # munmap(addr=t1, length=12288, prot=3, flags=34, fd=-1, offset=0)
    mv a0, t1
    li a1, 12288
    li a7, 215
    ecall
    mv t3, a0

    # Allocate a region larger than the new empty space
    # mmap(addr=NULL, length=16384, prot=3, flags=34, fd=-1, offset=0)
    li a0, 0
    li a1, 16384
    li a2, 3
    li a3, 34
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    mv t4, a0

    # Two allocations whose combined length equals the new empty space
    # mmap(addr=NULL, length=4096, prot=3, flags=34, fd=-1, offset=0)
    li a0, 0
    li a1, 4096
    li a2, 3
    li a3, 34
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    mv t5, a0

    # mmap(addr=NULL, length=8192, prot=3, flags=34, fd=-1, offset=0)
    li a0, 0
    li a1, 8192
    li a2, 3
    li a3, 34
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    mv t6, a0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), process_->getMmapStart());
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), process_->getMmapStart() + 4096);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), process_->getMmapStart() + 16384);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), process_->getMmapStart() + 20480);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), process_->getMmapStart() + 4096);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), process_->getMmapStart() + 8192);
}

TEST_P(Syscall, munmap) {
  // Test that no errors are given during expected usage
  RUN_RISCV(R"(
    # mmap(addr=NULL, length=65536, prot=3, flags=34, fd=-1, offset=0)
    li a0, 0
    li a1, 65536
    li a2, 3
    li a3, 34
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    mv t0, a0

    # munmap(addr=mmapStart_, length=65536, prot=3, flags=34, fd=-1, offset=0)
    mv a0, t0
    li a1, 65536
    li a7, 215
    ecall
    mv t1, a0

    # munmap(addr=mmapStart_, length=65536, prot=3, flags=34, fd=-1, offset=0)
    mv a0, t0
    li a1, 65536
    li a7, 215
    ecall
    mv t2, a0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), process_->getMmapStart());
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), 0);

  // Test that EINVAL error types trigger
  RUN_RISCV(R"(
    # mmap(addr=NULL, length=1024, prot=3, flags=34, fd=-1, offset=0)
    li a0, 0
    li a1, 1024
    li a2, 3
    li a3, 34
    li a4, -1
    li a5, 0
    li a7, 222
    ecall
    mv t0, a0

    # munmap(addr=mmapStart_, length=65536, prot=3, flags=34, fd=-1, offset=0)
    mv a0, t0
    li a1, 65536
    li a7, 215
    ecall
    mv t1, a0

    # munmap(addr=mmapStart_, length=65536, prot=3, flags=34, fd=-1, offset=0)
    addi t0, t0, 1024
    mv a0, t0
    li a1, 65536
    li a7, 215
    ecall
    mv t2, a0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), process_->getMmapStart() + 1024);
  EXPECT_EQ(getGeneralRegister<int64_t>(6), -1);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), -1);
}

TEST_P(Syscall, stdout) {
  const char str[] = "Hello, World!\n";
  for (char c : str) {
    initialHeapData_.push_back(c);
  }
  RUN_RISCV(R"(
    # load temporary for subtracts
    li t6, 32

    # Get heap address
    li a0, 0
    li a7, 214
    ecall

    # iovec = {{a0, 10}, {a0+10, 4}}
    sd a0, -32(sp)
    li a1, 10
    sd a1, -24(sp)
    addi a0, a0, 10
    sd a0, -16(sp)
    li a1, 4
    sd a1, -8(sp)

    # writev(fd=1, iov=iovec, iovcnt=2)
    li a0, 1
    sub a1, sp, t6
    li a2, 2
    li a7, 66
    ecall
  )");
  EXPECT_EQ(stdout_.substr(0, sizeof(str) - 1), str);
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), sizeof(str) - 1);
}

TEST_P(Syscall, mprotect) {
  // Check mprotect returns placeholder value as currently not implemented
  RUN_RISCV(R"(
    # mprotect(addr=47472, len=4096, prot=1) = 0
    li a0, 47472
    li a1, 4096
    li a2, 1
    li a7, 226
    ecall
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 0);
}

TEST_P(Syscall, newfstatat) {
  const char filepath[] = SIMENG_RISCV_TEST_ROOT "/data/input.txt";
  // Reserve 128 bytes for statbuf
  initialHeapData_.resize(128 + strlen(filepath) + 1);
  // Copy filepath to heap
  memcpy(initialHeapData_.data() + 128, filepath, strlen(filepath) + 1);

  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # newfstatat(dirfd=AT_FDCWD, filepath, statbuf, flags=0)
    li a0, -100
    add a1, t0, 128
    mv a2, t0
    li a3, 0
    li a7, 79
    ecall
    mv t1, a0
  )");
  // Check fstatat returned 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);

  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # newfstatat(dirfd=AT_FDCWD, wrongFilePath, statbuf, flags=0)
    li a0, -100
    addi a1, t0, 130
    mv a2, t0
    li a3, 0
    li a7, 79
    ecall
    mv t1, a0
  )");
  // Check fstatat returned -1 (file not found)
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -1);

  // Check syscall works using dirfd instead of AT_FDCWD
  const char file[] = "input.txt\0";
  char dirPath[LINUX_PATH_MAX];
  realpath(SIMENG_RISCV_TEST_ROOT "/data/\0", dirPath);

  initialHeapData_.resize(128 + strlen(dirPath) + strlen(file) + 2);
  // Copy dirPath to heap
  memcpy(initialHeapData_.data() + 128, file, strlen(file) + 1);
  memcpy(initialHeapData_.data() + 128 + strlen(file) + 1, dirPath,
         strlen(dirPath) + 1);
  RUN_RISCV(R"(
      # Get heap address
      li a0, 0
      li a7, 214
      ecall
      mv t0, a0

      # Need to open the directory
      # dfd = openat(AT_FDCWD, dirPath, O_RDONLY)
      # Flags = 0x0
      li a0, -100
      addi a1, t0, 138
      li a2, 0
      li a7, 56
      ecall
      mv t1, a0

      # newfstatat(dfd, file, statbuf, flags=0)
      mv a0, t1
      addi a1, t0, 128
      mv a2, t0
      li a3, 0
      li a7, 79
      ecall
      mv t1, a0
    )");
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 0);
}

TEST_P(Syscall, getrusage) {
  // Reserve 128 bytes for usage
  initialHeapData_.resize(128);
  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # getrusage(who = RUSAGE_SELF, usage)
    li a0, 0
    mv a1, t0
    li a7, 165
    ecall
    mv t1, a0

    # getrusage(who = RUSAGE_CHILDREN, usage)
    li a0, -1
    mv a1, t0
    li a7, 165
    ecall
    mv t2, a0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), 0);

  // MacOS doesn't support the final enum RUSAGE_THREAD
#ifndef __MACH__
  // Reserve 128 bytes for usage
  initialHeapData_.resize(128);
  RUN_RISCV(R"(
      # Get heap address
      li a0, 0
      li a7, 214
      ecall
      mv t0, a0

      # getrusage(who = RUSAGE_THREAD, usage)
      li a0, 1
      mv a1, t0
      li a7, 165
      ecall
      mv t1, a0
    )");
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 0);
#endif
}

TEST_P(Syscall, ftruncate) {
  const char filepath[] = SIMENG_RISCV_TEST_ROOT "/data/truncate-test.txt";

  // Copy filepath to heap
  initialHeapData_.resize(strlen(filepath) + 1);
  memcpy(initialHeapData_.data(), filepath, strlen(filepath) + 1);

  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # <input> = openat(AT_FDCWD, filepath, O_WRONLY, S_IRUSR)
    mv a1, t0
    li a0, -100
    li a2, 0x0001
    li a3, 400
    li a7, 56
    ecall
    mv t1, a0

    # ftruncate(fd, length) - increase length of file
    mv a0, t1
    li a1, 100
    li a7, 46
    ecall
    mv t2, a0

    # ftruncate(fd, length) - decrease length of file
    mv a0, t1
    li a1, 46
    li a7, 46
    ecall
    mv t3, a0

    # close(fd)
    mv a0, t1
    li a7, 57
    ecall
  )");
  // Check returned 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);
}

INSTANTIATE_TEST_SUITE_P(
    RISCV, Syscall,
    ::testing::Values(std::make_tuple(EMULATION, YAML::Load("{}")),
                      std::make_tuple(INORDER, YAML::Load("{}")),
                      std::make_tuple(OUTOFORDER, YAML::Load("{}"))),
    paramToString);

}  // namespace
