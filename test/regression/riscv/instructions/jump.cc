#include "RISCVRegressionTest.hh"

namespace {

using InstJump = RISCVRegressionTest;
using namespace simeng::arch::riscv::InstructionGroups;

TEST_P(InstJump, jalr) {
  RUN_RISCV(R"(
    li t1, 4
    jalr t0, t1, 12
    addi t6, t6, 10
    jalr ra, t1, 20
    addi t5, t5, 5
    jalr ra, t1, 4
    addi t4, t4, 3
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 10);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 16);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 8);

  EXPECT_GROUP(R"(jalr ra, t1, 4)", BRANCH);
}

TEST_P(InstJump, jalrAlias) {
  RUN_RISCV(R"(
    addi t0, t0, 12
    jalr t0
    addi t6, t6, 10
    addi t6, t6, 3
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 8);

  EXPECT_GROUP(R"(jalr t0)", BRANCH);

  RUN_RISCV(R"(
    addi ra, ra, 12
    ret               # jalr zero, ra, 0
    addi t6, t6, 10
    addi t6, t6, 3
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 12);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0);

  EXPECT_GROUP(R"(ret)", BRANCH);

  RUN_RISCV(R"(
    addi t0, t0, 12
    jr t0               # jalr zero, t0, 0
    addi t6, t6, 10
    addi t6, t6, 3
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0);

  EXPECT_GROUP(R"(jr t0)", BRANCH);
}

TEST_P(InstJump, jal) {
  RUN_RISCV(R"(
    jal t0, 12
    addi t6, t6, 10
    jal ra, 12
    addi t5, t5, 5
    jal ra, -12
    addi t4, t4, 3
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 10);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 12);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 4);

  EXPECT_GROUP(R"(jal ra, 12)", BRANCH);
}

TEST_P(InstJump, jalAlias) {
  RUN_RISCV(R"(
    j 12              #j 0xc
    addi t6, t6, 10
    jal t1, 12        #jal t1, 0xc
    addi t5, t5, 5
    jal -12           #jal -0xc
    addi t4, t4, 3
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 10);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 12);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 20);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0);

  EXPECT_GROUP(R"(j 12)", BRANCH);
  EXPECT_GROUP(R"(jal -12)", BRANCH);
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstJump,
                         ::testing::Values(std::make_tuple(EMULATION, "{}")),
                         paramToString);

}  // namespace
