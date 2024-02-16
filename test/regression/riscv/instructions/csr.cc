#include "RISCVRegressionTest.hh"

namespace {

using InstCSR = RISCVRegressionTest;

TEST_P(InstCSR, basicCsr) {
  std::cerr << "NEW TEST" << std::endl;
  std::cerr << "" << std::endl;
  std::cerr << "" << std::endl;

  RUN_RISCV(R"(
      addi x8, x9, 1
      li x8, 1
      csrrw x9, frm, x8
      addi x10, x9, 10
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 0b100000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 0b101010);
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstCSR,
                         ::testing::Values(std::make_tuple(EMULATION, "{}"),
                                           std::make_tuple(INORDER, "{}"),
                                           std::make_tuple(OUTOFORDER, "{}")),
                         paramToString);

}  // namespace