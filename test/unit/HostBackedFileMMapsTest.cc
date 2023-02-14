#include <fcntl.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iostream>

#include "gtest/gtest.h"
#include "simeng/kernel/Vma.hh"
#include "simeng/version.hh"

using namespace simeng::kernel;

namespace {

TEST(HostBackedFileMMapsTest, ExitOnInvalidFd) {
  HostBackedFileMMaps* hmap = new HostBackedFileMMaps();

  EXPECT_EXIT({ hmap->mapfd(-1, 0, 0); }, ::testing::ExitedWithCode(1),
              "fstat failed: Cannot create host backed file mmap for file "
              "descriptor - -1");
  EXPECT_EXIT({ hmap->mapfd(49, 0, 0); }, ::testing::ExitedWithCode(1),
              "fstat failed: Cannot create host backed file mmap for file "
              "descriptor - 49");
  delete hmap;
}

TEST(HostBackedFileMMapsTest, ExitOnOffsetGreaterThanFileSize) {
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/Data.txt";
  HostBackedFileMMaps* hmap = new HostBackedFileMMaps();

  int fd = open(fpath.c_str(), O_RDWR);
  ASSERT_NE(fd, -1);

  EXPECT_EXIT(
      { hmap->mapfd(fd, 0, 4096); }, ::testing::ExitedWithCode(1),
      "Tried to create host backed file mmap with offset and size greater "
      "than file size.");

  ASSERT_NE(close(fd), -1);
  delete hmap;
}

TEST(HostBackedFileMMapsTest, ExitOnSizeEqualsToZero) {
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/Data.txt";
  HostBackedFileMMaps* hmap = new HostBackedFileMMaps();

  int fd = open(fpath.c_str(), O_RDWR);
  ASSERT_NE(fd, -1);

  std::string errstr =
      "Cannot create host backed file mmap with size 0 for file descriptor: " +
      std::to_string(fd);

  EXPECT_EXIT({ hmap->mapfd(fd, 0, 0); }, ::testing::ExitedWithCode(1), errstr);

  ASSERT_NE(close(fd), -1);
  delete hmap;
}

TEST(HostBackedFileMMapsTest, ReadHostedFileZeroOffset) {
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/Data.txt";
  HostBackedFileMMaps* hmap = new HostBackedFileMMaps();

  int fd = open(fpath.c_str(), O_RDWR);
  ASSERT_NE(fd, -1);

  HostFileMMap* hfmm = hmap->mapfd(fd, 21, 0);
  ASSERT_LE(hfmm->flen_, 21);

  std::string text = "FileDescArrayTestData";
  char* ftext = new char[22];
  memset(ftext, '\0', 22);
  memcpy(ftext, hfmm->getfaddr(), hfmm->flen_);
  ASSERT_EQ(text, std::string(ftext));

  ASSERT_NE(close(fd), -1);
  delete hmap;
}

TEST(HostBackedFileMMapsTest, CreateHostedFileWithUnalignedOffset) {
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/Data.txt";
  HostBackedFileMMaps* hmap = new HostBackedFileMMaps();

  int fd = open(fpath.c_str(), O_RDWR);
  ASSERT_NE(fd, -1);

  uint64_t offset = 20;
  std::string errstr =
      "Failed to create Host backed file mapping. Offset is not aligned "
      "to page size: " +
      std::to_string(offset);

  EXPECT_EXIT({ hmap->mapfd(fd, 21, 20); }, ::testing::ExitedWithCode(1),
              errstr);

  ASSERT_NE(close(fd), -1);
  delete hmap;
}

TEST(HostBackedFileMMapsTest, ReadHostedFileNonZeroOffset) {
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/longtext.txt";
  HostBackedFileMMaps* hmap = new HostBackedFileMMaps();

  int fd = open(fpath.c_str(), O_RDWR);
  ASSERT_NE(fd, -1);

  HostFileMMap* hfmm = hmap->mapfd(fd, 8, 4096);
  ASSERT_LE(hfmm->flen_, 8);

  std::string text = "22222222";
  char* ftext = new char[9];
  memset(ftext, '\0', 9);
  memcpy(ftext, hfmm->getfaddr(), hfmm->flen_);
  ASSERT_EQ(text, std::string(ftext));

  ASSERT_NE(close(fd), -1);
  delete[] ftext;
  delete hmap;
}

}  // namespace
