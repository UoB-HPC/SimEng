#include "RISCVRegressionTest.hh"

namespace {

using InstCsr = RISCVRegressionTest;

TEST_P(InstCsr, cycle) {
  RUN_RISCV(R"(
     csrrw t1, frm, t1
   )");
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstCsr,
                         ::testing::Values(std::make_tuple(EMULATION,
                                                           YAML::Load("{}"))),
                         paramToString);

}  // namespace
