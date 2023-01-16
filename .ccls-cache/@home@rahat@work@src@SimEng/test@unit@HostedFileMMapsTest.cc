#include "gtest/gtest.h"
#include "simeng/kernel/Vma.hh"

using namespace simeng::kernel;

namespace {
TEST(HostBackedFileMMapsTest, EXIT) {
  EXPECT_EXIT({ std::cerr << "Hello 1" << std::endl; },
              ::testing::KilledBySignal(1), "Hello \\d");
}
}  // namespace
