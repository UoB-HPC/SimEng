#include <fcntl.h>
#include <unistd.h>

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
  std::string fpath = build_dir_path + "/test/unit/data/Data.txt";
  HostBackedFileMMaps* hmap = new HostBackedFileMMaps();

  int fd = open(fpath.c_str(), O_RDWR);
  ASSERT_NE(fd, -1);

  EXPECT_EXIT({ hmap->mapfd(fd, 0, 3000); }, ::testing::ExitedWithCode(1),
              "Tried to create host backed file mmap with offset greater "
              "than file size.");

  ASSERT_NE(close(fd), -1);
  delete hmap;
}

TEST(HostBackedFileMMapsTest, ExitOnSizeEqualsToZero) {
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/unit/data/Data.txt";
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
  std::string fpath = build_dir_path + "/test/unit/data/Data.txt";
  HostBackedFileMMaps* hmap = new HostBackedFileMMaps();

  int fd = open(fpath.c_str(), O_RDWR);
  ASSERT_NE(fd, -1);

  HostFileMMap* hfmm = hmap->mapfd(fd, 21, 0);
  ASSERT_LE(hfmm->fsize_, 21);

  std::string text = "FileDescArrayTestData";
  char* ftext = new char[22];
  memset(ftext, '\0', 22);
  memcpy(ftext, hfmm->getfaddr(), hfmm->fsize_);
  ASSERT_EQ(text, std::string(ftext));

  ASSERT_NE(close(fd), -1);
  delete hmap;
}

}  // namespace
