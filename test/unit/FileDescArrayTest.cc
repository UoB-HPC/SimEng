#include <fcntl.h>

#include <fstream>
#include <iostream>

#include "gtest/gtest.h"
#include "simeng/OS/FileDesc.hh"
#include "simeng/version.hh"

namespace {

using namespace simeng::OS;

TEST(FileDescArrayTest, InitialisesStandardFileDescriptors) {
  FileDescArray fdArr = FileDescArray();
  auto entry = fdArr.getFDEntry(0);
  ASSERT_EQ(entry.getFilename(), std::string("stdin"));
  entry = fdArr.getFDEntry(1);
  ASSERT_EQ(entry.getFilename(), std::string("stdout"));
  entry = fdArr.getFDEntry(2);
  ASSERT_EQ(entry.getFilename(), std::string("stderr"));
}

TEST(FileDescArrayTest, AllocatesFileDesc) {
  FileDescArray fdArr = FileDescArray();
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/Data.txt";
  int vfd = fdArr.allocateFDEntry(-1, fpath.c_str(), O_RDWR, 0666);
  ASSERT_NE(vfd, -1);
  auto entry = fdArr.getFDEntry(vfd);
  ASSERT_TRUE(entry.isValid());
  std::string text = "FileDescArrayTestData";
  char* ftext = new char[22];
  memset(ftext, '\0', 22);
  ASSERT_EQ(read(entry.getFd(), ftext, 21), 21);
  ASSERT_EQ(text, std::string(ftext));
  delete[] ftext;
}

TEST(FileDescArrayTest, RemovesFileDesc) {
  FileDescArray fdArr = FileDescArray();
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/Data.txt";
  int vfd = fdArr.allocateFDEntry(-1, fpath.c_str(), O_RDWR, 0666);
  ASSERT_NE(vfd, -1);
  auto entry = fdArr.getFDEntry(vfd);
  ASSERT_TRUE(entry.isValid());
  int hfd = entry.getFd();
  ASSERT_NE(fcntl(hfd, F_GETFD), -1);
  fdArr.removeFDEntry(vfd);
  entry = fdArr.getFDEntry(vfd);
  ASSERT_FALSE(entry.isValid());
  ASSERT_EQ(fcntl(hfd, F_GETFD), -1);
}

}  // namespace
