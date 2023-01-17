#include <fcntl.h>

#include "gtest/gtest.h"
#include "simeng/kernel/FileDesc.hh"
#include "simeng/version.hh"

namespace {
TEST(FileDescArrayTest, InitialisesStandardFileDescriptors) {
  FileDescArray* fdArr = new FileDescArray();
  auto entry = fdArr->getFDEntry(0);
  std::string fname(entry->filename_);
  ASSERT_EQ(fname, std::string("stdin"));
  entry = fdArr->getFDEntry(1);
  fname = entry->filename_;
  ASSERT_EQ(fname, std::string("stdout"));
  entry = fdArr->getFDEntry(2);
  fname = entry->filename_;
  ASSERT_EQ(fname, std::string("stderr"));
}

TEST(FileDescArrayTest, AllocatesFileDesc) {
  FileDescArray* fdArr = new FileDescArray();
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/unit/data/FileDescArrayData.txt";
  int vfd = fdArr->allocateFDEntry(-1, fpath.c_str(), O_RDWR, 0666);
  ASSERT_NE(vfd, -1);
  auto entry = fdArr->getFDEntry(vfd);
  ASSERT_NE(entry, nullptr);
  std::string text = "FileDescArrayTestData";
  char* ftext = new char[21];
  ASSERT_EQ(read(entry->fd_, ftext, 21), 21);
  ASSERT_EQ(text, std::string(ftext));
  delete[] ftext;
}

TEST(FileDescArrayTest, RemovesFileDesc) {
  FileDescArray* fdArr = new FileDescArray();
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/unit/data/FileDescArrayData.txt";
  int vfd = fdArr->allocateFDEntry(-1, fpath.c_str(), O_RDWR, 0666);
  ASSERT_NE(vfd, -1);
  auto entry = fdArr->getFDEntry(vfd);
  ASSERT_NE(entry, nullptr);
  int hfd = entry->fd_;
  ASSERT_NE(fcntl(hfd, F_GETFD), -1);
  fdArr->removeFDEntry(vfd);
  entry = fdArr->getFDEntry(vfd);
  ASSERT_EQ(entry, nullptr);
  ASSERT_EQ(fcntl(hfd, F_GETFD), -1);
}

}  // namespace
