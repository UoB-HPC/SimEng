#include "gtest/gtest.h"
#include "simeng/RegisterValue.hh"

namespace {

TEST(RegVal, tryTrue) {
  simeng::RegisterValue r = simeng::RegisterValue();
  EXPECT_TRUE(!r);
}

TEST(RegVal, tryData) {
  char* a = new char(8);
  simeng::RegisterValue r = simeng::RegisterValue(a, 8);
  EXPECT_FALSE(!r);
}

TEST(RegVal, trySize) {
  simeng::RegisterValue r = simeng::RegisterValue();
  ASSERT_EQ(r.size(), 0);
}

}  // namespace
