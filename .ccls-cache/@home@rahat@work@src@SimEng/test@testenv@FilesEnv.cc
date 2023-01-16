#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "simeng/version.hh"

namespace env {

class FilesEnv : public ::testing::Environment {
 private:
  std::vector<std::string> paths;

  void createLongtextFile() {
    std::string build_dir_path(SIMENG_BUILD_DIR);
    build_dir_path += "/test/longtext.txt";
    paths.push_back(build_dir_path);
    std::ofstream fs(build_dir_path);

    for (size_t i = 0; i < 4096; i++) {
      fs << 1;
    }
    for (size_t i = 0; i < 4096; i++) {
      fs << 2;
    }
    fs.close();
  }

  void createDataFile() {
    std::string build_dir_path(SIMENG_BUILD_DIR);
    build_dir_path += "/test/Data.txt";
    paths.push_back(build_dir_path);
    std::ofstream fs(build_dir_path);

    fs << "FileDescArrayTestData";
    fs.close();
  }

 public:
  ~FilesEnv() override{};

  // Override this to define how to set up the environment.
  // Create all files needed by tests.
  void SetUp() override {
    createLongtextFile();
    createDataFile();
  }

  // Override this to define how to tear down the environment.
  // Delete all created files.
  void TearDown() override {
    for (auto itr : paths) {
      std::string fpath = itr;
      if (!std::filesystem::remove(fpath)) {
        std::cerr << "Error occured while deleting file at path: " << fpath
                  << std::endl;
      }
    }
  }
};

testing::Environment* const env =
    testing::AddGlobalTestEnvironment(new FilesEnv);
}  // namespace env
