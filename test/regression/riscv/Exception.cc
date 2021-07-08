#include "RISCVRegressionTest.hh"

namespace {

using Exception = RISCVRegressionTest;

//// Test that branching to an address that is misaligned raises an exception.
//TEST_P(Exception, misaligned_pc) {
//  RUN_AARCH64(R"(
//    mov x0, 5
//    br x0
//  )");
//  const char err[] = "\nEncountered misaligned program counter exception";
//  EXPECT_EQ(stdout_.substr(0, sizeof(err) - 1), err);
//}
//
//INSTANTIATE_TEST_SUITE_P(AArch64, Exception,
//                         ::testing::Values(EMULATION, INORDER, OUTOFORDER),
//                         coreTypeToString);

}  // namespace
