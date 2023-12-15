#include "RISCVRegressionTest.hh"

namespace {

using InstCompressed = RISCVRegressionTest;

TEST_P(InstCompressed, flwsp) {
  RUN_RISCV(R"(
    c.fldsp fa5, 24(x2)
  )");
}

TEST_P(InstCompressed, swsp) {
  RUN_RISCV(R"(
    c.swsp t0, 24(x2)
  )");
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstCompressed,
                         ::testing::Values(std::make_tuple(EMULATION,
                                                           YAML::Load("{}"))),
                         paramToString);

}  // namespace
