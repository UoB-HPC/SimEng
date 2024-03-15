#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <string>

#include "AArch64RegressionTest.hh"

namespace {

using Syscall = AArch64RegressionTest;

/** The maximum size of a filesystem path. */
static const size_t LINUX_PATH_MAX = 4096;

TEST_P(Syscall, ioctl) {
  // TIOCGWINSZ: test it returns zero and sets the output to anything
  initialHeapData_.resize(8);
  memset(initialHeapData_.data(), -1, 8);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # ioctl(fd=1, request=TIOCGWINSZ, argp=x0)
    mov x2, x0
    mov x1, 0x5413
    mov x0, #1
    mov x8, #29
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 0);
  // Winsize changes between inside and outside of RUN_AARCH64 statement hence
  // we cannot reliably test against a known value
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 0), -1);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 2), -1);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 4), -1);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 6), -1);
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
    mov x1, #10
    mov x8, #46
    svc #0
    mov x23, x0

    # close(fd)
    mov x0, x21
    mov x8, #57
    svc #0
  )");
  // Check returned 0
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(22), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(23), 0);
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
  char* output =
      realpath(SIMENG_AARCH64_TEST_ROOT "/data/input.txt", abs_filepath);
  if (output == NULL) {
    // Something went wrong
    std::cerr << "[SimEng:syscall] realpath failed with errno = " << errno
              << std::endl;
    exit(EXIT_FAILURE);
  }

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
  output = realpath(SIMENG_AARCH64_TEST_ROOT "/data/\0", dirPath);
  if (output == NULL) {
    // Something went wrong
    std::cerr << "[SimEng:syscall] realpath failed with errno = " << errno
              << std::endl;
    exit(EXIT_FAILURE);
  }

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

TEST_P(Syscall, lseek) {
  const char filepath[] = SIMENG_AARCH64_TEST_ROOT "/data/input.txt";

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

    # lseek(fd=<input>, offset=8, whence=SEEK_SET) - seek to offset
    mov x0, x21
    mov x1, #8
    mov x2, #0
    mov x8, #62
    svc #0
    mov x22, x0

    # lseek(fd=<input>, offset=8, whence=SEEK_CUR) - seek to current location plus offset
    mov x0, x21
    mov x1, #8
    mov x2, #1
    mov x8, #62
    svc #0
    mov x23, x0

    # lseek(fd=<input>, offset=8, whence=SEEK_END) - seek to the size of the file plus offset
    mov x0, x21
    mov x1, #8
    mov x2, #2
    mov x8, #62
    svc #0
    mov x24, x0

    # close(fd)
    mov x0, x21
    mov x8, #57
    svc #0
  )");

  EXPECT_EQ(getGeneralRegister<int64_t>(22), 8);
  EXPECT_EQ(getGeneralRegister<int64_t>(23), 16);
  EXPECT_EQ(getGeneralRegister<int64_t>(24), 35);
}

// Test reading from and seeking through a file (tests openat, readv, read, and
// lseek syscalls)
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

    # lseek(fd=<input>, offset=0, whence=SEEK_SET)
    mov x0, x21
    mov x1, 0
    mov x2, 0
    mov x8, #62
    svc #0

    # read(fd=<input>, buf=sp, count=26)
    mov x0, x21
    sub x1, sp, 64
    mov x2, #26
    mov x8, #63
    svc #0

    # close(fd=<input>)
    mov x0, x21
    mov x8, #57
    svc #0
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

    # write(fd=<tempfile>, buf=x1, count=14)
    mov x0, x21
    mov x1, x20
    mov x2, #14
    mov x8, #64
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
  EXPECT_EQ(stdout_.substr(0, strlen(str)), str);
  EXPECT_EQ(getGeneralRegister<int64_t>(0), strlen(str));
}

// Tests that an openat syscall on a non-existent file returns an error value
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
  EXPECT_EQ(getGeneralRegister<int64_t>(0), -1);
}

// Test that readlinkat works for supported cases
TEST_P(Syscall, readlinkat) {
  const char path[] = "/proc/self/exe";
  //  // Get current directory and append the default program's command line
  //  // argument 0 value
  //  char cwd[LINUX_PATH_MAX];
  //  char* output = getcwd(cwd, LINUX_PATH_MAX);
  //  if (output == NULL) {
  //    // Something went wrong
  //    std::cerr << "[SimEng:syscall] getcwd failed with errno = " << errno
  //              << std::endl;
  //    exit(EXIT_FAILURE);
  //  }

  std::string reference =
      SIMENG_SOURCE_DIR + std::string("/SimEngDefaultProgram");

  // Copy path to heap
  initialHeapData_.resize(strlen(path) + reference.size() + 1);
  memcpy(initialHeapData_.data(), path, strlen(path) + 1);

  RUN_AARCH64(R"(
     # Get heap address
     mov x0, 0
     mov x8, 214
     svc #0
     mov x20, x0

     # readlinkat(dirfd=0, pathname=x20, buf=x20+15, bufsize=1024)
     mov x0, #0
     mov x1, x20
     add x2, x20, #15
     mov x3, #1024
     mov x8, #78
     svc #0
   )");

  EXPECT_EQ(getGeneralRegister<int64_t>(0), reference.size());
  char* data = processMemory_ + process_->getHeapStart() + 15;
  for (size_t i = 0; i < reference.size(); i++) {
    EXPECT_EQ(data[i], reference.c_str()[i]) << "at index i=" << i << '\n';
  }
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
  // Run fstatat syscall to define a reference
  struct ::stat statbufRef;
  ::fstatat(AT_FDCWD, filepath, &statbufRef, 0);

  // Check fstatat returned 0
  EXPECT_EQ(getGeneralRegister<int64_t>(21), 0);
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
  EXPECT_EQ(getGeneralRegister<int64_t>(21), -1);

  // Check syscall works using dirfd instead of AT_FDCWD
  const char file[] = "input.txt\0";
  char dirPath[LINUX_PATH_MAX];
  char* output = realpath(SIMENG_AARCH64_TEST_ROOT "/data/\0", dirPath);
  if (output == NULL) {
    // Something went wrong
    std::cerr << "[SimEng:syscall] realpath failed with errno = " << errno
              << std::endl;
    exit(EXIT_FAILURE);
  }

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
  // Run fstatat syscall to define a reference
  ::fstatat(AT_FDCWD, filepath, &statbufRef, 0);

  // Check fstatat returned 0
  EXPECT_EQ(getGeneralRegister<int64_t>(27), 0);

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
  const char filepath[] = SIMENG_AARCH64_TEST_ROOT "/data/input.txt";

  // Reserve 256 bytes for fstat struct
  initialHeapData_.resize(256 + strlen(filepath) + 1);

  // Copy filepath to heap
  memcpy(initialHeapData_.data() + 256, filepath, strlen(filepath) + 1);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x20, x0

    # <input> = openat(AT_FDCWD, filepath, O_RDONLY, S_IRUSR)
    mov x0, -100
    add x1, x20, 256
    mov x2, 0x0000
    mov x3, 400
    mov x8, #56
    svc #0
    mov x21, x0

    # fstat(fd=<input>, buf=x20)
    mov x0, x21
    mov x1, x20
    mov x8, #80
    svc #0
    mov x23, x0

    # close(fd=<input>)
    mov x0, x21
    mov x8, #57
    svc #0
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

TEST_P(Syscall, exit_group) {
  RUN_AARCH64(R"(
    # exit_group(1)
    mov x0, #1
    mov x8, #94
    svc #0
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
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x20, x0

    # set_tid_address(tidptr=x20)
    mov x0, x20
    mov x8, #96
    svc #0
    mov x21, x0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(21), 0);
}

// TODO: write futex test
// TODO: write set_robust_list test

TEST_P(Syscall, clock_gettime) {
  // Reserve 32 bytes for time data
  initialHeapData_.resize(32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x20, x0

    # Execute loop to elapse time in core
    mov x10, #10000
    subs x10, x10, #1
    b.ne #-4

    # clock_gettime(clk_id=CLOCK_REALTIME, tp=x20)
    mov x0, #0
    mov x1, x20
    mov x8, #113
    svc #0
    mov x21, x0

    # Execute loop to elapse time in core
    mov x10, #10000
    subs x10, x10, #1
    b.ne #-4

    # clock_gettime(clk_id=CLOCK_MONOTONIC, tp=x20+16)
    mov x0, #1
    add x1, x20, #16
    mov x8, #113
    svc #0
    mov x22, x0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(21), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(22), 0);
  // Set time values based on core model in use
  uint64_t secondsReal = 0;
  uint64_t nanosecondsReal = 0;
  uint64_t secondsMono = 0;
  uint64_t nanosecondsMono = 0;
  // Seconds will be 0 as too much host time would have to elapse in the test
  // suite for 1 simulated second to elapse
  if (std::get<0>(GetParam()) == EMULATION) {
    nanosecondsReal = 8003;
    nanosecondsMono = 16006;
  } else if (std::get<0>(GetParam()) == INORDER) {
    nanosecondsReal = 8006;
    nanosecondsMono = 16010;
  } else if (std::get<0>(GetParam()) == OUTOFORDER) {
    nanosecondsReal = 8009;
    nanosecondsMono = 16015;
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
  RUN_AARCH64(R"(
    # sched_setaffinity(pid=0, cpusetsize=1, mask=0)
    mov x0, #0
    mov x1, #1
    mov x2, #0
    mov x8, #122
    svc #0
    mov x21, x0

    # sched_setaffinity(pid=1, cpusetsize=1, mask=1)
    mov x0, #1
    mov x1, #1
    mov x2, #1
    mov x8, #122
    svc #0
    mov x22, x0

    # sched_setaffinity(pid=0, cpusetsize=0, mask=1)
    mov x0, #0
    mov x1, #0
    mov x2, #1
    mov x8, #122
    svc #0
    mov x23, x0

    # sched_setaffinity(pid=0, cpusetsize=1, mask=1)
    mov x0, #0
    mov x1, #1
    mov x2, #1
    mov x8, #122
    svc #0
    mov x24, x0
    )");
  EXPECT_EQ(getGeneralRegister<int64_t>(21), -EFAULT);
  EXPECT_EQ(getGeneralRegister<int64_t>(22), -ESRCH);
  EXPECT_EQ(getGeneralRegister<int64_t>(23), -EINVAL);
  EXPECT_EQ(getGeneralRegister<int64_t>(24), 0);
}

// TODO: tests only test errored instances of using sched_getaffinity due to
// omitted functionality. Redo test once functionality is implemented
TEST_P(Syscall, sched_getaffinity) {
  RUN_AARCH64(R"(
    # schedGetAffinity(pid=0, cpusetsize=0, mask=0)
    mov x0, #0
    mov x1, #0
    mov x2, #0
    mov x8, #123
    svc #0
    mov x21, x0

    # sched_getaffinity(pid=1, cpusetsize=0, mask=1)
    mov x0, #1
    mov x1, #0
    mov x2, #1
    mov x8, #123
    svc #0
    mov x22, x0

    # sched_getaffinity(pid=0, cpusetsize=0, mask=1)
    mov x0, #0
    mov x1, #0
    mov x2, #1
    mov x8, #123
    svc #0
    mov x23, x0
    )");
  EXPECT_EQ(getGeneralRegister<int64_t>(21), -1);
  EXPECT_EQ(getGeneralRegister<int64_t>(22), -1);
  EXPECT_EQ(getGeneralRegister<int64_t>(23), 1);
}

// TODO: write tgkill test
// TODO: write rt_sigaction test
// TODO: write rt_sigprocmask test

TEST_P(Syscall, uname) {
  // Reserve 325 bytes for utsname struct
  initialHeapData_.resize(325);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x20, x0

    # getrusage(buf=x20)
    mov x0, x20
    mov x8, #160
    svc #0
    mov x21, x0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(21), 0);

  // Check utsname struct in memory
  char* data = processMemory_ + process_->getHeapStart();
  const char sysname[] = "Linux";
  for (size_t i = 0; i < strlen(sysname); i++) EXPECT_EQ(data[i], sysname[i]);

  // Add 65 to data pointer for reserved length of each string field in Linux
  data += 65;
  const char nodename[] = "simeng.hpc.cs.bris.ac.uk";
  for (size_t i = 0; i < strlen(nodename); i++) EXPECT_EQ(data[i], nodename[i]);

  data += 65;
  const char release[] = "4.14.0";
  for (size_t i = 0; i < strlen(release); i++) EXPECT_EQ(data[i], release[i]);

  data += 65;
  const char version[] = "#1 SimEng Mon Apr 29 16:28:37 UTC 2019";
  for (size_t i = 0; i < strlen(version); i++) EXPECT_EQ(data[i], version[i]);

  data += 65;
  const char machine[] = "aarch64";
  for (size_t i = 0; i < strlen(machine); i++) EXPECT_EQ(data[i], machine[i]);
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
  // getrusage rusage struct values changes between inside and outside of
  // RUN_AARCH64 statement hence we cannot reliably test against a known value.
  // Thus only test return value
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

TEST_P(Syscall, gettimeofday) {
  // Reserve 64 bytes for time data
  initialHeapData_.resize(64);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x20, x0

    # Execute loop to elapse time in core
    mov x10, #10000
    subs x10, x10, #1
    b.ne #-4

    # gettimeofday(tv=x20, tz=null)
    mov x0, x20
    mov x1, #0
    mov x8, #169
    svc #0
    mov x21, x0

    # Execute loop to elapse time in core
    mov x10, #10000
    subs x10, x10, #1
    b.ne #-4

    # gettimeofday(tv=null, tz=x20+16)
    mov x0, #0
    add x1, x20, #16
    mov x8, #169
    svc #0
    mov x22, x0

    # Execute loop to elapse time in core
    mov x10, #10000
    subs x10, x10, #1
    b.ne #-4

    # gettimeofday(tv=x20+32, tz=x20+48)
    add x0, x20, #32
    add x1, x20, #48
    mov x8, #169
    svc #0
    mov x23, x0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(21), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(22), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(23), 0);

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
  RUN_AARCH64(R"(
    # gettid()
    mov x8, #178
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 0);
}

TEST_P(Syscall, getpid) {
  RUN_AARCH64(R"(
    # getpid()
    mov x8, #172
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 0);
}

TEST_P(Syscall, getuid) {
  RUN_AARCH64(R"(
    # getuid()
    mov x8, #174
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 0);
}

TEST_P(Syscall, geteuid) {
  RUN_AARCH64(R"(
    # geteuid()
    mov x8, #175
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 0);
}

TEST_P(Syscall, getgid) {
  RUN_AARCH64(R"(
    # getgid()
    mov x8, #176
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 0);
}

TEST_P(Syscall, getegid) {
  RUN_AARCH64(R"(
    # getegid()
    mov x8, #177
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 0);
}

// TODO: write sysinfo test
// TODO: write shutdown test

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
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 0);
}

// TODO: write mbind test
// TODO: write prlimit64 test
// TODO: write rseq test

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
  EXPECT_EQ(getGeneralRegister<int64_t>(9), process_->getMmapStart());
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
  EXPECT_EQ(getGeneralRegister<int64_t>(9), process_->getMmapStart() + 1024);
  EXPECT_EQ(getGeneralRegister<int64_t>(10), -1);
  EXPECT_EQ(getGeneralRegister<int64_t>(11), -1);
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
  EXPECT_EQ(getGeneralRegister<int64_t>(9), process_->getMmapStart());
  EXPECT_EQ(getGeneralRegister<int64_t>(10), process_->getMmapStart() + 65536);
  EXPECT_EQ(getGeneralRegister<int64_t>(11), process_->getMmapStart() + 69632);

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
  EXPECT_EQ(getGeneralRegister<int64_t>(9), process_->getMmapStart());
  EXPECT_EQ(getGeneralRegister<int64_t>(10), process_->getMmapStart() + 4096);
  EXPECT_EQ(getGeneralRegister<int64_t>(11), process_->getMmapStart() + 16384);
  EXPECT_EQ(getGeneralRegister<int64_t>(12), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(13), process_->getMmapStart() + 20480);
  EXPECT_EQ(getGeneralRegister<int64_t>(14), process_->getMmapStart() + 4096);
  EXPECT_EQ(getGeneralRegister<int64_t>(15), process_->getMmapStart() + 8192);
}

TEST_P(Syscall, getrandom) {
  initialHeapData_.resize(24);
  memset(initialHeapData_.data(), -1, 16);

  RUN_AARCH64(R"(
      # Get heap address
      mov x0, 0
      mov x8, 214
      svc #0

      # store initial heap address
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

  // Check that the returned bytes from the two syscalls don't all match.
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
    AArch64, Syscall,
    ::testing::Values(std::make_tuple(EMULATION, "{}"),
                      std::make_tuple(INORDER, "{}"),
                      std::make_tuple(OUTOFORDER,
                                      "{L1-Data-Memory: "
                                      "{Interface-Type: Fixed}}")),
    paramToString);

}  // namespace
