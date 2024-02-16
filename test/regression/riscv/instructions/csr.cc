#include "RISCVRegressionTest.hh"

namespace {

using InstCSR = RISCVRegressionTest;

TEST_P(InstCSR, basicCsr) {
  std::cerr << "NEW TEST" << std::endl;
  std::cerr << "" << std::endl;
  std::cerr << "" << std::endl;

  RUN_RISCV(R"(
      li x8, 1
      csrrw x9, frm, x8
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 0b100000);
}

INSTANTIATE_TEST_SUITE_P(
    RISCV, InstCSR,
    ::testing::Values(
        //        std::make_tuple(EMULATION, "{}"),
        //                      std::make_tuple(INORDER, "{}"),
        std::make_tuple(OUTOFORDER, "{}")),
    //            "{Ports: {'0': {Portname: 0, Instruction-Group-Support: [INT,
    //            " "LOAD, STORE, BRANCH]}}}")),
    paramToString);

}  // namespace