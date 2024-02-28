#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <string>

#include "RISCVRegressionTest.hh"

namespace {

using Syscall = RISCVRegressionTest;

/** The maximum size of a filesystem path. */
static const size_t LINUX_PATH_MAX = 4096;

TEST_P(Syscall, ioctl) {
  // TIOCGWINSZ: test it returns zero and sets the output to anything
  initialHeapData_.resize(8);
  memset(initialHeapData_.data(), -1, 8);
  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall

    # ioctl(fd=1, request=TIOCGWINSZ, argp=a0)
    mv a2, a0
    li a1, 0x5413
    li a0, 1
    li a7, 29
    ecall
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(10), 0);
  // Winsize changes between inside and outside of RUN_RISCV statement hence
  // we cannot reliably test against a known value
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 0), -1);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 2), -1);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 4), -1);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 6), -1);
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
    li a1, 10
    li a7, 46
    ecall
    mv t3, a0

    # close(fd)
    mv a0, t1
    li a7, 57
    ecall
  )");
  // Check returned 0
  EXPECT_EQ(getGeneralRegister<int64_t>(10), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(28), 0);
  // Check file has been truncated
  std::ifstream truncatedFileI(filepath);
  std::string fileContents;
  getline(truncatedFileI, fileContents);
  truncatedFileI.close();
  EXPECT_EQ(fileContents, "This is a ");
  // Reset file
  std::ofstream truncatedFileO(filepath);
  truncatedFileO << "This is a test file for the ftruncate syscall";
  truncatedFileO.close();
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

TEST_P(Syscall, lseek) {
  const char filepath[] = SIMENG_RISCV_TEST_ROOT "/data/input.txt";

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
    li a0, -100
    mv a1, t0
    li a2, 0x0000
    li a3, 400
    li a7, 56
    ecall
    mv t1, a0

    # lseek(fd=<input>, offset=8, whence=SEEK_SET) - seek to offset
    mv a0, t1
    li a1, 8
    li a2, 0
    li a7, 62
    ecall
    mv t2, a0

    # lseek(fd=<input>, offset=8, whence=SEEK_CUR) - seek to current location plus offset
    mv a0, t1
    li a1, 8
    li a2, 1
    li a7, 62
    ecall
    mv t3, a0

    # lseek(fd=<input>, offset=8, whence=SEEK_END) - seek to the size of the file plus offset
    mv a0, t1
    li a1, 8
    li a2, 2
    li a7, 62
    ecall
    mv t4, a0

    # close(fd)
    mv a0, t1
    li a7, 57
    ecall
  )");

  EXPECT_EQ(getGeneralRegister<int64_t>(7), 8);
  EXPECT_EQ(getGeneralRegister<int64_t>(28), 16);
  EXPECT_EQ(getGeneralRegister<int64_t>(29), 35);
}

// Test reading from and seeking through a file (tests openat, readv, read, and
// lseek syscalls)
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
    
    # lseek(fd=<input>, offset=0, whence=SEEK_SET)
    mv a0, t1
    li a1, 0
    li a2, 0
    li a7, 62
    ecall    
    
    # read(fd=<input>, buf=sp, count=26)
    mv a0, t1
    li t5, 64 
    sub a1, sp, t5
    li a2, 26
    li a7, 63
    ecall

    # close(fd=<input>)
    mv a0, t1
    li a7, 57
    ecall
  )");

  // Check result of readv operations
  const char refReadv[] = "ABCD\0UV\0EFGH\0\0\0\0MNOPQRST";
  char* dataReadv = processMemory_ + process_->getHeapStart();
  for (size_t i = 0; i < strlen(refReadv); i++) {
    EXPECT_EQ(dataReadv[i], refReadv[i]) << "at index i=" << i << '\n';
  }

  // Check result of read operation
  const char refRead[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  char* dataRead = processMemory_ + process_->getInitialStackPointer() - 64;
  for (size_t i = 0; i < strlen(refRead); i++) {
    EXPECT_EQ(dataRead[i], refRead[i]) << "at index i=" << i << '\n';
  }
}

// Test reading from and seeking through a file (tests openat, writev, and write
// syscalls)
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

    # write(fd=<tempfile>, buf=a1, count=14)
    mv a0, t1
    mv a1, t0
    li a2, 14
    li a7, 64
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
  outfile.read(outdata, 14);
  EXPECT_FALSE(outfile.eof());
  EXPECT_EQ(strncmp(str, outdata, 14), 0);
  outfile.read(outdata, 15);
  EXPECT_TRUE(outfile.eof());
  EXPECT_EQ(strncmp(str, outdata, 14), 0);
}

// Tests that writing to the standard out file descriptor functions correctly
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
  EXPECT_EQ(stdout_.substr(0, strlen(str)), str);
  EXPECT_EQ(getGeneralRegister<int64_t>(10), strlen(str));
}

// Tests that an openat syscall on a non-existent file returns an error value
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
  EXPECT_EQ(getGeneralRegister<int64_t>(10), -1);
}

// Test that readlinkat works for supported cases
TEST_P(Syscall, readlinkat) {
  const char path[] = "/proc/self/exe";
  // Get current directory and append the default program's comannd line
  // argument 0 value
  char cwd[LINUX_PATH_MAX];
  getcwd(cwd, LINUX_PATH_MAX);
  std::string reference = std::string(cwd) + std::string("/Default");
  // Copy path to heap
  initialHeapData_.resize(strlen(path) + reference.size() + 1);
  memcpy(initialHeapData_.data(), path, strlen(path) + 1);

  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # readlinkat(dirfd=0, pathname=t0, buf=x20+15, bufsize=1024)
    li a0, 0
    mv a1, t0
    add a2, t0, 15
    li a3, 1024
    li a7, 78
    ecall
  )");

  EXPECT_EQ(getGeneralRegister<int64_t>(10), reference.size());
  char* data = processMemory_ + process_->getHeapStart() + 15;
  for (size_t i = 0; i < reference.size(); i++) {
    EXPECT_EQ(data[i], reference.c_str()[i]) << "at index i=" << i << '\n';
  }
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
  // Run fstatat syscall to define a reference
  struct ::stat statbufRef;
  ::fstatat(AT_FDCWD, filepath, &statbufRef, 0);

  // Check fstatat returned 0
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 0);
  // Check fstatat buf matches reference
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart()),
            statbufRef.st_dev);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 8),
            statbufRef.st_ino);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 16),
            statbufRef.st_mode);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 20),
            statbufRef.st_nlink);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 24),
            statbufRef.st_uid);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 28),
            statbufRef.st_gid);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 32),
            statbufRef.st_rdev);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 40), 0ull);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 48),
            statbufRef.st_size);
  EXPECT_EQ(getMemoryValue<int32_t>(process_->getHeapStart() + 56),
            statbufRef.st_blksize);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 60), 0ull);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 64),
            statbufRef.st_blocks);
#ifdef __MACH__
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 72),
            statbufRef.st_atimespec.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 80),
            statbufRef.st_atimespec.tv_nsec);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 88),
            statbufRef.st_mtimespec.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 96),
            statbufRef.st_mtimespec.tv_nsec);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 104),
            statbufRef.st_ctimespec.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 112),
            statbufRef.st_ctimespec.tv_nsec);
#else
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 72),
            statbufRef.st_atim.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 80),
            statbufRef.st_atim.tv_nsec);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 88),
            statbufRef.st_mtim.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 96),
            statbufRef.st_mtim.tv_nsec);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 104),
            statbufRef.st_ctim.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 112),
            statbufRef.st_ctim.tv_nsec);
#endif
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 116), 0ull);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 124), 0ull);

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
  EXPECT_EQ(getGeneralRegister<int64_t>(6), -1);

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
    )");  // Run fstatat syscall to define a reference
  ::fstatat(AT_FDCWD, filepath, &statbufRef, 0);

  // Check fstatat returned 0
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 0);

  // Check fstatat buf matches reference
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart()),
            statbufRef.st_dev);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 8),
            statbufRef.st_ino);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 16),
            statbufRef.st_mode);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 20),
            statbufRef.st_nlink);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 24),
            statbufRef.st_uid);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 28),
            statbufRef.st_gid);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 32),
            statbufRef.st_rdev);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 40), 0ull);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 48),
            statbufRef.st_size);
  EXPECT_EQ(getMemoryValue<int32_t>(process_->getHeapStart() + 56),
            statbufRef.st_blksize);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 60), 0ull);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 64),
            statbufRef.st_blocks);
#ifdef __MACH__
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 72),
            statbufRef.st_atimespec.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 80),
            statbufRef.st_atimespec.tv_nsec);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 88),
            statbufRef.st_mtimespec.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 96),
            statbufRef.st_mtimespec.tv_nsec);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 104),
            statbufRef.st_ctimespec.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 112),
            statbufRef.st_ctimespec.tv_nsec);
#else
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 72),
            statbufRef.st_atim.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 80),
            statbufRef.st_atim.tv_nsec);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 88),
            statbufRef.st_mtim.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 96),
            statbufRef.st_mtim.tv_nsec);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 104),
            statbufRef.st_ctim.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 112),
            statbufRef.st_ctim.tv_nsec);
#endif
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 116), 0ull);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 124), 0ull);
}

TEST_P(Syscall, fstat) {
  const char filepath[] = SIMENG_RISCV_TEST_ROOT "/data/input.txt";

  // Reserve 256 bytes for fstat struct
  initialHeapData_.resize(256 + strlen(filepath) + 1);

  // Copy filepath to heap
  memcpy(initialHeapData_.data() + 256, filepath, strlen(filepath) + 1);

  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # <input> = openat(AT_FDCWD, filepath, O_RDONLY, S_IRUSR)
    li a0, -100
    add a1, t0, 256
    li a2, 0x0000
    li a3, 400
    li a7, 56
    ecall
    mv t1, a0

    # fstat(fd=<input>, buf=t0)
    mv a0, t1
    mv a1, t0
    li a7, 80
    ecall
    mv t2, a0

    # close(fd=<input>)
    mv a0, t1
    li a7, 57
    ecall
  )");
  // Run fstat syscall to define a reference
  int64_t fd = ::openat(AT_FDCWD, filepath, O_RDONLY, S_IRUSR);
  struct ::stat statbufRef;
  ::fstat(fd, &statbufRef);
  ::close(fd);

  // Check fstat returned 0
  EXPECT_EQ(getGeneralRegister<int64_t>(23), 0);
  // Check fstat buf matches reference
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart()),
            statbufRef.st_dev);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 8),
            statbufRef.st_ino);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 16),
            statbufRef.st_mode);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 20),
            statbufRef.st_nlink);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 24),
            statbufRef.st_uid);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 28),
            statbufRef.st_gid);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 32),
            statbufRef.st_rdev);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 40), 0ull);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 48),
            statbufRef.st_size);
  EXPECT_EQ(getMemoryValue<int32_t>(process_->getHeapStart() + 56),
            statbufRef.st_blksize);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 60), 0ull);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 64),
            statbufRef.st_blocks);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 72),
            statbufRef.st_atime);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 80), 0ull);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 88),
            statbufRef.st_mtime);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 96), 0ull);
  EXPECT_EQ(getMemoryValue<int64_t>(process_->getHeapStart() + 104),
            statbufRef.st_ctime);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 112), 0ull);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 116), 0ull);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 124), 0ull);
}

TEST_P(Syscall, exit) {
  RUN_RISCV(R"(
    # exit(1)
    li a0, 1
    li a7, 93
    ecall
  )");
  // Set reference for stdout
  std::string str =
      "\n[SimEng:ExceptionHandler] Received exit syscall: terminating "
      "with exit code 1";
  EXPECT_EQ(stdout_.substr(0, str.size()), str);
}

TEST_P(Syscall, exit_group) {
  RUN_RISCV(R"(
    # exit_group(1)
    li a0, 1
    li a7, 94
    ecall
  )");
  // Set reference for stdout
  std::string str =
      "\n[SimEng:ExceptionHandler] Received exit_group syscall: terminating "
      "with exit code 1";
  EXPECT_EQ(stdout_.substr(0, str.size()), str);
}

TEST_P(Syscall, set_tid_address) {
  // Reserve 8 bytes for tid
  initialHeapData_.resize(8);
  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # set_tid_address(tidptr=t0)
    mv a0, t0
    li a7, 96
    ecall
    mv t1, a0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 0);
}

// TODO: write futex test
// TODO: write set_robust_list test

TEST_P(Syscall, clock_gettime) {
  // Reserve 32 bytes for time data
  initialHeapData_.resize(32);

  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # Execute loop to elapse time in core
    li t3, 10000
    li t4, 1
    sub t3, t3, t4
    bne zero, t3, -4

    # clock_gettime(clk_id=CLOCK_REALTIME, tp=t0)
    li a0, 0
    mv a1, t0
    li a7, 113
    ecall
    mv t1, a0

    # Execute loop to elapse time in core
    li t3, 10000
    li t4, 1
    sub t3, t3, t4
    bne zero, t3, -4

    # clock_gettime(clk_id=CLOCK_MONOTONIC, tp=t0+16)
    li a0, 1
    add a1, t0, 16
    li a7, 113
    ecall
    mv t2, a0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), 0);
  // Set time values based on core model in use
  uint64_t secondsReal = 0;
  uint64_t nanosecondsReal = 0;
  uint64_t secondsMono = 0;
  uint64_t nanosecondsMono = 0;
  // Seconds will be 0 as too much host time would have to elapse in the test
  // suite for 1 simulated second to elapse
  if (std::get<0>(GetParam()) == EMULATION) {
    nanosecondsReal = 8004;
    nanosecondsMono = 16007;
  } else if (std::get<0>(GetParam()) == INORDER) {
    nanosecondsReal = 8006;
    nanosecondsMono = 16011;
  } else if (std::get<0>(GetParam()) == OUTOFORDER) {
    nanosecondsReal = 8010;
    nanosecondsMono = 16016;
  }

  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart()), secondsReal);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 8),
            nanosecondsReal);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 16),
            secondsMono);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 24),
            nanosecondsMono);
}

// TODO: tests only test errored instances of using sched_setaffinity due to
// omitted functionality. Redo test once functionality is implemented
TEST_P(Syscall, sched_setaffinity) {
  RUN_RISCV(R"(
    # sched_setaffinity(pid=0, cpusetsize=1, mask=0)
    li a0, 0
    li a1, 1
    li a2, 0
    li a7, 122
    ecall
    mv t0, a0

    # sched_setaffinity(pid=1, cpusetsize=1, mask=1)
    li a0, 1
    li a1, 1
    li a2, 1
    li a7, 122
    ecall
    mv t1, a0

    # sched_setaffinity(pid=0, cpusetsize=0, mask=1)
    li a0, 0
    li a1, 0
    li a2, 1
    li a7, 122
    ecall
    mv t2, a0

    # sched_setaffinity(pid=0, cpusetsize=1, mask=1)
    li a0, 0
    li a1, 1
    li a2, 1
    li a7, 122
    ecall
    mv t3, a0
    )");
  EXPECT_EQ(getGeneralRegister<int64_t>(5), -EFAULT);
  EXPECT_EQ(getGeneralRegister<int64_t>(6), -ESRCH);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), -EINVAL);
  EXPECT_EQ(getGeneralRegister<int64_t>(28), 0);
}

// TODO: tests only test errored instances of using sched_getaffinity due to
// omitted functionality. Redo test once functionality is implemented
TEST_P(Syscall, sched_getaffinity) {
  RUN_RISCV(R"(
    # schedGetAffinity(pid=0, cpusetsize=0, mask=0)
    li a0, 0
    li a1, 0
    li a2, 0
    li a7, 123
    ecall
    mv t0, a0

    # sched_getaffinity(pid=1, cpusetsize=0, mask=1)
    li a0, 1
    li a1, 0
    li a2, 1
    li a7, 123
    ecall
    mv t1, a0

    # sched_getaffinity(pid=0, cpusetsize=0, mask=1)
    li a0, 0
    li a1, 0
    li a2, 1
    li a7, 123
    ecall
    mv t2, a0
    )");
  EXPECT_EQ(getGeneralRegister<int64_t>(5), -1);
  EXPECT_EQ(getGeneralRegister<int64_t>(6), -1);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), 1);
}

// TODO: write tgkill test
// TODO: write rt_sigaction test
// TODO: write rt_sigprocmask test

TEST_P(Syscall, uname) {
  // Reserve 325 bytes for utsname struct
  initialHeapData_.resize(325);

  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # getrusage(buf=t0)
    mv a0, t0
    li a7, 160
    ecall
    mv t1, a0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 0);

  // Check utsname struct in memory
  char* data = processMemory_ + process_->getHeapStart();
  const char sysname[] = "Linux";
  for (size_t i = 0; i < strlen(sysname); i++) EXPECT_EQ(data[i], sysname[i]);

  // Add 65 to data pointer for reserved length of each string field in Linux
  data += 65;
  const char nodename[] = "fedora-riscv";
  for (size_t i = 0; i < strlen(nodename); i++) EXPECT_EQ(data[i], nodename[i]);

  data += 65;
  const char release[] = "5.5.0-0.rc5.git0.1.1.riscv64.fc32.riscv64";
  for (size_t i = 0; i < strlen(release); i++) EXPECT_EQ(data[i], release[i]);

  data += 65;
  const char version[] = "#1 SMP Mon Jan 6 17:31:22 UTC 2020";
  for (size_t i = 0; i < strlen(version); i++) EXPECT_EQ(data[i], version[i]);

  data += 65;
  const char machine[] = "riscv64";
  for (size_t i = 0; i < strlen(machine); i++) EXPECT_EQ(data[i], machine[i]);

  data += 65;
  const char domainname[] = "(none)";
  for (size_t i = 0; i < strlen(domainname); i++)
    EXPECT_EQ(data[i], domainname[i]);
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
  // getrusage rusage struct values changes between inside and outside of
  // RUN_RISCV statement hence we cannot reliably test against a known value.
  // Thus only test return value
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

TEST_P(Syscall, gettimeofday) {
  // Reserve 64 bytes for time data
  initialHeapData_.resize(64);

  RUN_RISCV(R"(
    # Get heap address
    li a0, 0
    li a7, 214
    ecall
    mv t0, a0

    # Execute loop to elapse time in core
    li t3, 10000
    li t4, 1
    sub t3, t3, t4
    bne zero, t3, -4

    # gettimeofday(tv=t0, tz=null)
    mv a0, t0
    li a1, 0
    li a7, 169
    ecall
    mv t1, a0

    # Execute loop to elapse time in core
    li t3, 10000
    li t4, 1
    sub t3, t3, t4
    bne zero, t3, -4

    # gettimeofday(tv=null, tz=t0+16)
    li a0, 0
    add a1, t0, 16
    li a7, 169
    ecall
    mv t2, a0

    # Execute loop to elapse time in core
    li t3, 10000
    li t4, 1
    sub t3, t3, t4
    bne zero, t3, -4

    # gettimeofday(tv=t0+32, tz=t0+48)
    add a0, t0, 32
    add a1, t0, 48
    li a7, 169
    ecall
    mv t3, a0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(28), 0);

  // Set time values based on core model in use

  // Seconds will be 0 as too much host time would have to elapse in the test
  // suite for 1 simulated second to elapse
  simeng::kernel::timeval tvLoop0 = {0, 8};
  // tv set to NULL here so no value change will occur
  simeng::kernel::timeval tvLoop2 = {0, 24};
  // All tz values are set to 0 given values are the displacement from GMT
  simeng::kernel::timeval tzLoop1 = {0, 0};
  simeng::kernel::timeval tzLoop2 = {0, 0};

  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart()), tvLoop0.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 8),
            tvLoop0.tv_usec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 16),
            tzLoop1.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 24),
            tzLoop1.tv_usec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 32),
            tvLoop2.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 40),
            tvLoop2.tv_usec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 48),
            tzLoop2.tv_sec);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 56),
            tzLoop2.tv_usec);
}

TEST_P(Syscall, gettid) {
  RUN_RISCV(R"(
    # gettid()
    li a7, 178
    ecall
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(10), 0);
}

TEST_P(Syscall, getpid) {
  RUN_RISCV(R"(
    # getpid()
    li a7, 172
    ecall
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(10), 0);
}

TEST_P(Syscall, getuid) {
  RUN_RISCV(R"(
    # getuid()
    li a7, 174
    ecall
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(10), 0);
}

TEST_P(Syscall, geteuid) {
  RUN_RISCV(R"(
    # geteuid()
    li a7, 175
    ecall
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(10), 0);
}

TEST_P(Syscall, getgid) {
  RUN_RISCV(R"(
    # getgid()
    li a7, 176
    ecall
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(10), 0);
}

TEST_P(Syscall, getegid) {
  RUN_RISCV(R"(
    # getegid()
    li a7, 177
    ecall
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(10), 0);
}

// TODO: write sysinfo test
// TODO: write shutdown test

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
  EXPECT_EQ(getGeneralRegister<int64_t>(10), 0);
}

// TODO: write mbind test
// TODO: write prlimit64 test
// TODO: write rseq test

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
  EXPECT_EQ(getGeneralRegister<int64_t>(5), process_->getMmapStart());
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
  EXPECT_EQ(getGeneralRegister<int64_t>(5), process_->getMmapStart() + 1024);
  EXPECT_EQ(getGeneralRegister<int64_t>(6), -1);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), -1);
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
  EXPECT_EQ(getGeneralRegister<int64_t>(5), process_->getMmapStart());
  EXPECT_EQ(getGeneralRegister<int64_t>(6), process_->getMmapStart() + 65536);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), process_->getMmapStart() + 69632);

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
  EXPECT_EQ(getGeneralRegister<int64_t>(5), process_->getMmapStart());
  EXPECT_EQ(getGeneralRegister<int64_t>(6), process_->getMmapStart() + 4096);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), process_->getMmapStart() + 16384);
  EXPECT_EQ(getGeneralRegister<int64_t>(28), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(29), process_->getMmapStart() + 20480);
  EXPECT_EQ(getGeneralRegister<int64_t>(30), process_->getMmapStart() + 4096);
  EXPECT_EQ(getGeneralRegister<int64_t>(31), process_->getMmapStart() + 8192);
}

TEST_P(Syscall, getrandom) {
  initialHeapData_.resize(24);
  memset(initialHeapData_.data(), -1, 16);

  RUN_RISCV(R"(
      # Get heap address
      li a0, 0
      li a7, 214
      ecall

      # store initial heap address
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

  // Check that the returned bytes aren't all equal to -1.
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
  // If they do then the returned bytes surely weren't random
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

INSTANTIATE_TEST_SUITE_P(
    RISCV, Syscall,
    ::testing::Values(std::make_tuple(EMULATION, "{}"),
                      std::make_tuple(INORDER, "{}"),
                      std::make_tuple(OUTOFORDER,
                                      "{L1-Data-Memory: "
                                      "{Interface-Type: Fixed}}")),
    paramToString);
}  // namespace
