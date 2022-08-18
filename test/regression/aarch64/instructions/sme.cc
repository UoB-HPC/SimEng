#include <algorithm>
#include <limits>

#include "AArch64RegressionTest.hh"

namespace {

using InstSme = AArch64RegressionTest;

#if SIMENG_LLVM_VERSION >= 15
TEST_P(InstSme, tmp) {
  // This is a temporary blank test
  RUN_AARCH64(R"(
    smstart
    smstop
  )");
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstSme,
                         ::testing::ValuesIn(genCoreTypeSVLPairs(EMULATION)),
                         paramToString);
#else
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(InstSme);
#endif

}  // namespace