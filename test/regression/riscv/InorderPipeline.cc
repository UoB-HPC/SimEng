#include "RISCVRegressionTest.hh"

namespace {

using inorderPipeline = RISCVRegressionTest;

TEST_P(inorderPipeline, prematureMulticycleHalting) {
  RUN_RISCV(R"(
    li a1, 2
    li a2, 1
    li a4, 5

    beq a1, a2, end # mispredict with target out of programByteLength creates
                    # pipeline bubble
    div a3, a1, a2  # multicycle instruction ties up execution unit causing
                    # decode to halt and next instruction to be stuck in the
                    # tail of pipelined buffer
    beq a1, a2, end # mispredict with target out of programByteLength halts
                    # fetch unit this only occurs because the instruction
                    # address is set after decode therefor a garbage value is
                    # used sometimes causing the halt at ~FetchUnit.cc::177

    # This sequence of instructions with this inorder pipeline causes all
    # buffers to appear empty and the fetch unit to halt causing the inorder
    # core to halt early which is incorrect behaviour. This is fixed in PR 294

    li a4, 10       # Occurs if core does not halt
    end:
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(14), 10);
}

INSTANTIATE_TEST_SUITE_P(RISCV, inorderPipeline,
                         ::testing::Values(std::make_tuple(INORDER,
                                                           YAML::Load("{}"))),
                         paramToString);

}  // namespace
