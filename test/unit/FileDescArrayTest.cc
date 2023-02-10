#include <fcntl.h>

#include <filesystem>
#include <fstream>
#include <iostream>

#include "gtest/gtest.h"
#include "simeng/kernel/FileDesc.hh"
#include "simeng/version.hh"

namespace {
namespace env {

class DataEnv : public ::testing::Environment {
 private:
  std::string fpath;

 public:
  ~DataEnv() override {}

  // Override this to define how to set up the environment.
  // Create a file with size greater than 4096 to test offsets.
  // This needs to be done because offset has to be a multiple of pageSize,
  // other mmap will fail.
  void SetUp() override {
    std::string build_dir_path(SIMENG_BUILD_DIR);
    fpath = build_dir_path + "/test/unit/Data.txt";

    std::ofstream fs(fpath);

    fs << "FileDescArrayTestData";
    fs.close();
  }

  // Override this to define how to tear down the environment.
  // Delete the created longtext.txt file.
  void TearDown() override {
    if (!std::filesystem::remove(fpath)) {
      std::cerr << "Error occured while deleting Data.txt file at path: "
                << fpath << std::endl;
    }
  }
};

testing::Environment* const env =
    testing::AddGlobalTestEnvironment(new DataEnv);
}  // namespace env

TEST(FileDescArrayTest, InitialisesStandardFileDescriptors) {
  FileDescArray fdArr = FileDescArray();
  auto entry = fdArr.getFDEntry(0);
  ASSERT_EQ(entry.filename(), std::string("stdin"));
  entry = fdArr.getFDEntry(1);
  ASSERT_EQ(entry.filename(), std::string("stdout"));
  entry = fdArr.getFDEntry(2);
  ASSERT_EQ(entry.filename(), std::string("stderr"));
}

// This test will only pass if cmake --build build --target install command is
// execute. Just builiding the test suite and running from the build directory
// will not include the data folder which is needed for this test case to pass.
//
TEST(FileDescArrayTest, AllocatesFileDesc) {
  FileDescArray fdArr = FileDescArray();
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/unit/Data.txt";
  int vfd = fdArr.allocateFDEntry(-1, fpath.c_str(), O_RDWR, 0666);
  ASSERT_NE(vfd, -1);
  auto entry = fdArr.getFDEntry(vfd);
  ASSERT_TRUE(entry.isValid());
  std::string text = "FileDescArrayTestData";
  char* ftext = new char[22];
  memset(ftext, '\0', 22);
  ASSERT_EQ(read(entry.fd(), ftext, 21), 21);
  ASSERT_EQ(text, std::string(ftext));
  delete[] ftext;
}

// This test will only pass if cmake --build build --target install command is
// executed. Just builiding the test suite and running from the build directory
// will not include the data folder which is needed for this test case to pass.
//
TEST(FileDescArrayTest, RemovesFileDesc) {
  FileDescArray fdArr = FileDescArray();
  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/unit/Data.txt";
  int vfd = fdArr.allocateFDEntry(-1, fpath.c_str(), O_RDWR, 0666);
  ASSERT_NE(vfd, -1);
  auto entry = fdArr.getFDEntry(vfd);
  ASSERT_TRUE(entry.isValid());
  int hfd = entry.fd();
  ASSERT_NE(fcntl(hfd, F_GETFD), -1);
  fdArr.removeFDEntry(vfd);
  entry = fdArr.getFDEntry(vfd);
  ASSERT_FALSE(entry.isValid());
  ASSERT_EQ(fcntl(hfd, F_GETFD), -1);
}

}  // namespace
