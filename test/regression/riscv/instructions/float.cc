#include "RISCVRegressionTest.hh"

namespace {

using InstFloat = RISCVRegressionTest;

TEST_P(InstFloat, FLD) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall
    fld ft0, 0(a0)
    fld ft1, 8(a0)
    fld ft2, 16(a0)
    fld ft3, 24(a0)
  )");

  EXPECT_EQ(getFPRegister<double>(0), 1.0);
  EXPECT_EQ(getFPRegister<double>(1), 123.456);
  EXPECT_EQ(getFPRegister<double>(2), -0.00032);
  EXPECT_EQ(getFPRegister<double>(3), 123456);
}

TEST_P(InstFloat, FSD) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall
    fld ft0, 0(a0)
    fld ft1, 8(a0)
    fld ft2, 16(a0)
    fld ft3, 24(a0)
    fsd ft3, 0(a0)
    fsd ft2, 8(a0)
    fsd ft1, 16(a0)
    fsd ft0, 24(a0)
  )");

  EXPECT_EQ(getFPRegister<double>(0), 1.0);
  EXPECT_EQ(getFPRegister<double>(1), 123.456);
  EXPECT_EQ(getFPRegister<double>(2), -0.00032);
  EXPECT_EQ(getFPRegister<double>(3), 123456);

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 64);

  EXPECT_EQ(getMemoryValue<double>(64), 123456);
  EXPECT_EQ(getMemoryValue<double>(72), -0.00032);
  EXPECT_EQ(getMemoryValue<double>(80), 123.456);
  EXPECT_EQ(getMemoryValue<double>(88), 1.0);
}

TEST_P(InstFloat, FADD_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall
    fld ft0, 0(a0)
    fld ft1, 8(a0)
    fld ft2, 16(a0)
    fld ft3, 24(a0)
    fadd.d ft4, ft0, ft1
    fadd.d ft5, ft1, ft2
  )");

  EXPECT_EQ(getFPRegister<double>(4), 124.456);
  EXPECT_EQ(getFPRegister<double>(5), 123.456 - 0.00032);
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstFloat,
                         ::testing::Values(std::make_tuple(EMULATION,
                                                           YAML::Load("{}"))),
                         paramToString);

}  // namespace