#include <fcntl.h>
#include <unistd.h>

#include <filesystem>>
#include <fstream>
#include <iostream>

#include "gtest/gtest.h"
#include "simeng/kernel/Vma.hh"
#include "simeng/version.hh"

using namespace simeng::kernel;

namespace {

namespace env {

class HBFMTestEnv : public ::testing::Environment {
 private:
  std::string fpath;

 public:
  ~HBFMTestEnv() override {}

  // Override this to define how to set up the environment.
  // Create a file with size greater than 4096 to test offsets.
  // This needs to be done because offset has to be a multiple of pageSize,
  // other mmap will fail.
  void SetUp() override {
    std::string build_dir_path(SIMENG_BUILD_DIR);
    fpath = build_dir_path + "/test/unit/data/longtext.txt";

    std::ofstream fs(fpath);

    for (size_t i = 0; i < 2048; i++) {
      fs << 4096;
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
    testing::AddGlobalTestEnvironment(new HBFMTestEnv);
}  // namespace env

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

  EXPECT_EXIT(
      { hmap->mapfd(fd, 0, 4096); }, ::testing::ExitedWithCode(1),
      "Tried to create host backed file mmap with offset and size greater "
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
  std::string fpath = build_dir_path + "/test/unit/data/Data.txt";
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
  std::string fpath = build_dir_path + "/test/unit/data/longtext.txt";
  HostBackedFileMMaps* hmap = new HostBackedFileMMaps();

  int fd = open(fpath.c_str(), O_RDWR);
  ASSERT_NE(fd, -1);

  HostFileMMap* hfmm = hmap->mapfd(fd, 8, 4096);
  ASSERT_LE(hfmm->flen_, 8);

  std::string text = "40964096";
  char* ftext = new char[9];
  memset(ftext, '\0', 9);
  memcpy(ftext, hfmm->getfaddr(), hfmm->flen_);
  ASSERT_EQ(text, std::string(ftext));

  ASSERT_NE(close(fd), -1);
  delete hmap;
}

}  // namespace
