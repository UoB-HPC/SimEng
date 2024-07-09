#include "RISCVRegressionTest.hh"

namespace {

using InstFloat = RISCVRegressionTest;
using namespace simeng::arch::riscv::InstructionGroups;

static constexpr uint64_t boxedPositiveNan = 0xffffffff7fc00000;

// All test verified with qemu

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

  EXPECT_GROUP(R"(fld ft3, 24(a0))", LOAD_FLOAT);
}

TEST_P(InstFloat, FLW) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;

  RUN_RISCV(R"(
     # Get heap address
     li a7, 214
     ecall

     flw ft0, 0(a0)
     flw ft1, 4(a0)
     flw ft2, 8(a0)
     flw ft3, 12(a0)
   )");

  // Check bit values to avoid discrepancies with rounding

  EXPECT_EQ(getFPRegister<uint32_t>(0), 0x3f800000);
  EXPECT_EQ(getFPRegister<uint32_t>(1), 0x42f6e979);
  EXPECT_EQ(getFPRegister<uint32_t>(2), 0xb9a7c5ac);
  EXPECT_EQ(getFPRegister<uint32_t>(3), 0x47f12000);

  EXPECT_EQ(getFPRegister<float>(0), (float)1.0);
  EXPECT_EQ(getFPRegister<float>(1), (float)123.456);
  EXPECT_EQ(getFPRegister<float>(2), (float)-0.00032);
  EXPECT_EQ(getFPRegister<float>(3), (float)123456);

  // Check bit values as NaNs comparison results in false even if equivalent

  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xffffffff42f6e979);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xffffffffb9a7c5ac);
  EXPECT_EQ(getFPRegister<uint64_t>(3), 0xffffffff47f12000);

  EXPECT_GROUP(R"( flw ft3, 12(a0))", LOAD_FLOAT);
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

  EXPECT_GROUP(R"(fsd ft0, 24(a0))", STORE_FLOAT);
}

TEST_P(InstFloat, FSW) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;

  RUN_RISCV(R"(
     # Get heap address
     li a7, 214
     ecall

     fld ft0, 0(a0)
     fld ft1, 4(a0)
     flw ft2, 8(a0)
     flw ft3, 12(a0)

     fsw ft3, 0(a0)
     fsw ft2, 4(a0)
     fsw ft1, 8(a0)
     fsw ft0, 12(a0)
   )");

  EXPECT_EQ(getFPRegister<uint64_t>(0), 0x42f6e9793f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xb9a7c5ac42f6e979);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xffffffffb9a7c5ac);
  EXPECT_EQ(getFPRegister<uint64_t>(3), 0xffffffff47f12000);
  EXPECT_EQ(getFPRegister<float>(2), (float)-0.00032);
  EXPECT_EQ(getFPRegister<float>(3), (float)123456);

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 64);

  EXPECT_EQ(getMemoryValue<float>(64), (float)123456);
  EXPECT_EQ(getMemoryValue<float>(68), (float)-0.00032);
  EXPECT_EQ(getMemoryValue<float>(72), (float)123.456);
  EXPECT_EQ(getMemoryValue<float>(76), (float)1.0);

  EXPECT_GROUP(R"(fsw ft0, 12(a0))", STORE_FLOAT);
}

TEST_P(InstFloat, FDIV_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)

    fdiv.d fa6, fa5, fa3
    fdiv.d ft0, fa5, fa4
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(15), (double)999.212341);
  EXPECT_EQ(getFPRegister<double>(16), (double)999.212341 / (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(0), (double)999.212341 / (double)-3.78900003);

  EXPECT_GROUP(R"(fdiv.d ft0, fa5, fa4)", FLOAT_DIV_OR_SQRT);
}

TEST_P(InstFloat, FDIV_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)

    fdiv.s fa6, fa5, fa3
    fdiv.s ft0, fa5, fa4
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);
  EXPECT_EQ(getFPRegister<float>(16), (float)999.212341 / (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(0), (float)999.212341 / (float)-3.78900003);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fdiv.s fa5, fa3, fa3  # 1 / 1 = 1
    fdiv.s fa6, fa4, fa3  # Incorrect NaN box should be caught by fdiv and
                          # canonical NaN used as input, NaN / 1 = NaN
   )");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_GROUP(R"(fdiv.s ft0, fa5, fa4)", FLOAT_DIV_OR_SQRT);
}

TEST_P(InstFloat, FMUL_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)

    fmul.d fa6, fa5, fa3
    fmul.d ft0, fa5, fa4
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(15), (double)999.212341);
  EXPECT_EQ(getFPRegister<double>(16), (double)999.212341 * (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(0), (double)999.212341 * (double)-3.78900003);

  EXPECT_GROUP(R"(fmul.d ft0, fa5, fa4)", FLOAT_MUL);
}

TEST_P(InstFloat, FMUL_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)

    fmul.s fa6, fa5, fa3
    fmul.s ft0, fa5, fa4
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);
  EXPECT_EQ(getFPRegister<float>(16), (float)999.212341 * (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(0), (float)999.212341 * (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xFFFFFFFFC56CA040);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fmul.s fa5, fa3, fa3  # 1 * 1 = 1
    fmul.s fa6, fa4, fa3  # Incorrect NaN box should be caught by fmul and
                          # canonical NaN used as input, NaN * 1 = NaN
   )");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_GROUP(R"(fmul.s ft0, fa5, fa4)", FLOAT_MUL);
}

TEST_P(InstFloat, FCVT_D_L) {
  RUN_RISCV(R"(
    li t0, 123
    li t1, -1

    fcvt.d.l ft0, t0
    fcvt.d.l ft1, t1
   )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 123);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -1);

  EXPECT_EQ(getFPRegister<double>(0), (double)123);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0x405EC00000000000);
  EXPECT_EQ(getFPRegister<double>(1), (double)-1);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xBFF0000000000000);

  EXPECT_GROUP(R"(fcvt.d.l ft1, t1)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_D_W) {
  RUN_RISCV(R"(
    li t0, 23456
    li t1, -1
    li t2, 0xFFFFFFFF0FFFFFFF

    fcvt.d.w ft0, t0
    fcvt.d.w ft1, t1
    fcvt.d.w ft2, t2
   )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 23456);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), -4026531841);

  EXPECT_EQ(getFPRegister<double>(0), (double)23456);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0x40D6E80000000000);
  EXPECT_EQ(getFPRegister<double>(1), (double)-1);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xBFF0000000000000);
  EXPECT_EQ(getFPRegister<double>(2), (double)268435455);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0x41AFFFFFFE000000);

  EXPECT_GROUP(R"(fcvt.d.w ft1, t1)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_S_L) {
  RUN_RISCV(R"(
    li t0, 23456
    li t1, -1
    li t2, 0xFFFFFFFF0FFFFFFF

    fcvt.s.l ft0, t0
    fcvt.s.l ft1, t1
    fcvt.s.l ft2, t2
   )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 23456);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), -4026531841);

  EXPECT_EQ(getFPRegister<float>(0), (float)23456);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xFFFFFFFF46b74000);
  EXPECT_EQ(getFPRegister<float>(1), (float)-1);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xFFFFFFFFbf800000);
  EXPECT_EQ(getFPRegister<float>(2), (float)-4026531841);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xFFFFFFFFCF700000);

  EXPECT_GROUP(R"(fcvt.s.l ft1, t1)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_S_W) {
  RUN_RISCV(R"(
    li t0, 23456
    li t1, -1
    li t2, 0xFFFFFFFF0FFFFFFF

    fcvt.s.w ft0, t0
    fcvt.s.w ft1, t1
    fcvt.s.w ft2, t2
   )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 23456);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), -4026531841);

  EXPECT_EQ(getFPRegister<float>(0), (float)23456);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xFFFFFFFF46b74000);
  EXPECT_EQ(getFPRegister<float>(1), (float)-1);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xFFFFFFFFbf800000);
  EXPECT_EQ(getFPRegister<float>(2), (float)268435455);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xFFFFFFFF4d800000);

  EXPECT_GROUP(R"(fcvt.s.w ft1, t1)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_W_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    # Set rounding mode to nearest ties to even
    li a1, 0
    fsrm a1

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)
    fld fa6, 24(a0)

    fcvt.w.d t0, fa3      # should convert to 5
    fcvt.w.d t3, fa3, rtz # should convert to 4
    fcvt.w.d t1, fa4      # should convert to -4
    fcvt.w.d t4, fa4, rtz # should convert to -3
    fcvt.w.d t2, fa6 #Nan converts to 0x7fffffff in integer reg
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0x7FF8000000000000);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFFFFFFFFC);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0xFFFFFFFFFFFFFFFD);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0x000000007FFFFFFF);

  EXPECT_GROUP(R"(fcvt.w.d t0, fa3)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_W_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)
    flw fa6, 12(a0)

    fcvt.w.s t0, fa3      # should convert to 5
    fcvt.w.s t3, fa3, rtz # should convert to 4
    fcvt.w.s t1, fa4      # should convert to -4
    fcvt.w.s t4, fa4, rtz # should convert to -3
    fcvt.w.s t2, fa6 #Nan converts to 0x7fffffff in integer reg
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFFFFFFFFC);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0xFFFFFFFFFFFFFFFD);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0x000000007FFFFFFF);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fcvt.w.s t0, fa3 # fcvt 1 = 1
    fcvt.w.s t1, fa4 # Incorrect NaN box should be caught by fcvt and
                          # canonical NaN used as input, fcvt NaN = 2^31 − 1
)");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x0000000000000001);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6),
            pow(2, 31) - 1);  // Expected result from spec
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x000000007fffffff);

  EXPECT_GROUP(R"(fcvt.w.s t0, fa3)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_L_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)
    fld fa6, 24(a0)

    fcvt.l.d t0, fa3      # should convert to 5
    fcvt.l.d t3, fa3, rtz # should convert to 4
    fcvt.l.d t1, fa4      # should convert to -4
    fcvt.l.d t4, fa4, rtz # should convert to -3
    fcvt.l.d t2, fa6 #Nan converts to 0x7fffffff in integer reg
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0x7FF8000000000000);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFFFFFFFFC);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0xFFFFFFFFFFFFFFFD);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0x7FFFFFFFFFFFFFFF);

  EXPECT_GROUP(R"(fcvt.l.d t0, fa3)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_L_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)
    flw fa6, 12(a0)

    fcvt.l.s t0, fa3      # should convert to 5
    fcvt.l.s t3, fa3, rtz # should convert to 4
    fcvt.l.s t1, fa4      # should convert to -4
    fcvt.l.s t4, fa4, rtz # should convert to -3
    fcvt.l.s t2, fa6 #Nan converts to 0x7fffffff in integer reg
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFFFFFFFFC);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0xFFFFFFFFFFFFFFFD);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0x7FFFFFFFFFFFFFFF);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fcvt.l.s t0, fa3 # fcvt 1 = 1
    fcvt.l.s t1, fa4 # Incorrect NaN box should be caught by fcvt and
                          # canonical NaN used as input, fcvt NaN = 2^31 − 1
)");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x0000000000000001);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6),
            (uint64_t)pow(2, 63) - 1);  // Expected result from spec

  EXPECT_GROUP(R"(fcvt.l.s t0, fa3)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_LU_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 1.8446744073709552e+19;  // 2^64 - 1
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)
    fld fa6, 24(a0)

    fcvt.lu.d t0, fa3      # should convert to 5
    fcvt.lu.d t3, fa3, rtz # should convert to 4
    fcvt.lu.d t1, fa4      # should convert to 0
    fcvt.lu.d t4, fa4, rtz # should convert to 0
    fcvt.lu.d t2, fa6 #Nan converts to 0x7fffffff in integer reg
    fcvt.lu.d t5, fa5
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(15), 0x43F0000000000000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0x7FF8000000000000);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0xFFFFFFFFFFFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0xFFFFFFFFFFFFFFFF);

  EXPECT_GROUP(R"(fcvt.lu.d t0, fa3)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_WU_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 1.8446744073709552e+19;  // 2^64 - 1
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)
    fld fa6, 24(a0)

    fcvt.wu.d t0, fa3      # should convert to 5
    fcvt.wu.d t3, fa3, rtz # should convert to 4
    fcvt.wu.d t1, fa4      # should convert to 0
    fcvt.wu.d t4, fa4, rtz # should convert to 0
    fcvt.wu.d t2, fa6 #Nan converts to 0xffffffffffffffff in integer reg
    fcvt.wu.d t5, fa5
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(15), 0x43F0000000000000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0x7FF8000000000000);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0xFFFFFFFFFFFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0xFFFFFFFFFFFFFFFF);

  EXPECT_GROUP(R"(fcvt.wu.d t0, fa3)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_LU_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 1.8446744073709552e+19;  // 2^64 - 1
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)
    flw fa6, 12(a0)

    fcvt.lu.s t0, fa3      # should convert to 5
    fcvt.lu.s t3, fa3, rtz # should convert to 4
    fcvt.lu.s t1, fa4      # should convert to 0
    fcvt.lu.s t4, fa4, rtz # should convert to 0
    fcvt.lu.s t2, fa6 #Nan converts to 0x7fffffff in integer reg
    fcvt.lu.s t5, fa5
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xFFFFFFFF5F800000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0xFFFFFFFFFFFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0xFFFFFFFFFFFFFFFF);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fcvt.lu.s t0, fa3 # fcvt 1 = 1
    fcvt.lu.s t1, fa4 # Incorrect NaN box should be caught by fcvt and
                          # canonical NaN used as input, fcvt NaN = 2^32 − 1
)");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x0000000000000001);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6),
            0xFFFFFFFFFFFFFFFF);  // Expected result from spec

  EXPECT_GROUP(R"(fcvt.lu.s t0, fa3)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_WU_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 1.8446744073709552e+19;  // 2^64 - 1
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)
    flw fa6, 12(a0)

    fcvt.wu.s t0, fa3      # should convert to 5
    fcvt.wu.s t3, fa3, rtz # should convert to 4
    fcvt.wu.s t1, fa4      # should convert to 0
    fcvt.wu.s t4, fa4, rtz # should convert to 0
    fcvt.wu.s t2, fa6 #Nan converts to 0x7fffffff in integer reg
    fcvt.wu.s t5, fa5
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xFFFFFFFF5F800000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0xFFFFFFFFFFFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0xFFFFFFFFFFFFFFFF);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fcvt.wu.s t0, fa3 # fcvt 1 = 1
    fcvt.wu.s t1, fa4 # Incorrect NaN box should be caught by fcvt and
                          # canonical NaN used as input, fcvt NaN = 2^32 − 1
)");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x0000000000000001);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6),
            pow(2, 32) - 1);  // Expected result from spec
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFFFFFFFFF);

  EXPECT_GROUP(R"(fcvt.wu.s t0, fa3)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_D_WU) {
  RUN_RISCV(R"(
    li t0, 23456
    li t1, -1
    li t2, 0xFFFFFFFF0FFFFFFF

    fcvt.d.wu ft0, t0
    fcvt.d.wu ft1, t1
    fcvt.d.wu ft2, t2
   )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 23456);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), -4026531841);

  EXPECT_EQ(getFPRegister<double>(0), (double)23456);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0x40D6E80000000000);
  EXPECT_EQ(getFPRegister<double>(1), (double)4294967295);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0x41EFFFFFFFE00000);
  EXPECT_EQ(getFPRegister<double>(2), (double)268435455);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0x41AFFFFFFE000000);

  EXPECT_GROUP(R"(fcvt.d.wu ft0, t0)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_S_WU) {
  RUN_RISCV(R"(
    li t0, 23456
    li t1, -1
    li t2, 0xFFFFFFFF0FFFFFFF

    fcvt.s.wu ft0, t0
    fcvt.s.wu ft1, t1
    fcvt.s.wu ft2, t2
   )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 23456);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), -4026531841);

  EXPECT_EQ(getFPRegister<float>(0), (float)23456);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xFFFFFFFF46b74000);
  EXPECT_EQ(getFPRegister<float>(1), (float)4294967295);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xFFFFFFFF4F800000);
  EXPECT_EQ(getFPRegister<float>(2), (float)268435456);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xFFFFFFFF4D800000);

  EXPECT_GROUP(R"(fcvt.s.wu ft0, t0)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_D_LU) {
  RUN_RISCV(R"(
    li t0, 23456
    li t1, -1
    li t2, 0xFFFFFFFF0FFFFFFF

    fcvt.d.lu ft0, t0
    fcvt.d.lu ft1, t1
    fcvt.d.lu ft2, t2
   )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 23456);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), -4026531841);

  EXPECT_EQ(getFPRegister<double>(0), (double)23456);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0x40D6E80000000000);
  EXPECT_EQ(getFPRegister<double>(1), (double)1.8446744073709551616e+19);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0x43F0000000000000);
  EXPECT_EQ(getFPRegister<double>(2), (double)1.8446744069683019776e+19);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0x43EFFFFFFFE20000);

  EXPECT_GROUP(R"(fcvt.d.lu ft0, t0)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_S_LU) {
  RUN_RISCV(R"(
    li t0, 23456
    li t1, -1
    li t2, 0xFFFFFFFF0FFFFFFF

    fcvt.s.lu ft0, t0
    fcvt.s.lu ft1, t1
    fcvt.s.lu ft2, t2
   )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 23456);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), -4026531841);

  EXPECT_EQ(getFPRegister<float>(0), (float)23456);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xFFFFFFFF46b74000);
  EXPECT_EQ(getFPRegister<float>(1), (float)1.84467440737e+19);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xFFFFFFFF5F800000);
  EXPECT_EQ(getFPRegister<float>(2), (float)1.84467440737e+19);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xFFFFFFFF5F800000);

  EXPECT_GROUP(R"(fcvt.s.lu ft0, t0)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FMADD_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)

    fmadd.d fa6, fa3, fa5, fa4
    fmadd.d fa7, fa5, fa4, fa3
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(15), (double)999.212341);
  EXPECT_EQ(getFPRegister<double>(16), (4.52432537 * 999.212341) + -3.78900003);
  EXPECT_EQ(getFPRegister<double>(17), (999.212341 * -3.78900003) + 4.52432537);

  EXPECT_GROUP(R"(fmadd.d fa6, fa3, fa5, fa4)", FLOAT_MUL);
}

TEST_P(InstFloat, FMADD_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)

    fmadd.s fa6, fa5, fa4, fa3 # (999.212341 * -3.78900003) + 4.52432537
    fmadd.s fa7, fa4, fa3, fa5
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);
  EXPECT_EQ(getFPRegister<float>(16),
            ((float)999.212341 * (float)-3.78900003) + (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(16), (float)-3781.49121);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0xFFFFFFFFC56C57DC);
  EXPECT_EQ(getFPRegister<uint64_t>(17), 0xFFFFFFFF44758476);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fmadd.s fa5, fa3, fa3, fa3  # (1 * 1) + 1 = 2
    fmadd.s fa6, fa4, fa3, fa3  # Incorrect NaN box should be caught by fmadd and
                          # canonical NaN used as input, (NaN * 1) + 1 = NaN
    fmadd.s fa7, fa3, fa4, fa3
    fmadd.s fs2, fa3, fa3, fa4
   )");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xffffffff40000000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);
  EXPECT_EQ(getFPRegister<uint64_t>(17), boxedPositiveNan);
  EXPECT_EQ(getFPRegister<uint64_t>(18), boxedPositiveNan);

  EXPECT_GROUP(R"(fmadd.s fa7, fa4, fa3, fa5)", FLOAT_MUL);
}

TEST_P(InstFloat, FNMSUB_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)
                                # Counter intuitively sums with the product
    fnmsub.d fa6, fa5, fa4, fa3 # -(999.212341 * -3.78900003) + 4.52432537
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(15), (double)999.212341);
  EXPECT_EQ(getFPRegister<double>(16),
            -(999.212341 * -3.78900003) + 4.52432537);

  EXPECT_GROUP(R"(fnmsub.d fa6, fa5, fa4, fa3)", FLOAT_MUL);
}

TEST_P(InstFloat, FNMSUB_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)
                                # Counter intuitively sums with the product
    fnmsub.s fa6, fa5, fa4, fa3 # -(999.212341 * -3.78900003) + 4.52432537
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);
  EXPECT_EQ(getFPRegister<float>(16),
            -((float)999.212341 * (float)-3.78900003) + (float)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0xFFFFFFFF456CE8A4);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fnmsub.s fa5, fa3, fa3, fa3  # -(1 * 1) + 1 = 0
    fnmsub.s fa6, fa4, fa3, fa3  # Incorrect NaN box should be caught by fmadd and
                          # canonical NaN used as input, -(NaN * 1) + 1 = NaN
    fnmsub.s fa7, fa3, fa4, fa3
    fnmsub.s fs2, fa3, fa3, fa4
   )");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xffffffff00000000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);
  EXPECT_EQ(getFPRegister<uint64_t>(17), boxedPositiveNan);
  EXPECT_EQ(getFPRegister<uint64_t>(18), boxedPositiveNan);

  EXPECT_GROUP(R"(fnmsub.s fa6, fa5, fa4, fa3)", FLOAT_MUL);
}

TEST_P(InstFloat, FMSUB_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)

    fmsub.s fa6, fa5, fa4, fa3 # (999.212341 * -3.78900003) - 4.52432537
    fmsub.s fa7, fa4, fa3, fa5
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);
  EXPECT_EQ(getFPRegister<float>(16),
            ((float)999.212341 * (float)-3.78900003) - (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(16), (float)-3790.54004);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0xFFFFFFFFC56CE8A4);
  EXPECT_EQ(getFPRegister<uint64_t>(17), 0xFFFFFFFFC47E16B8);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fmsub.s fa5, fa3, fa3, fa3  # (1 * 1) - 1 = 0
    fmsub.s fa6, fa4, fa3, fa3  # Incorrect NaN box should be caught by fmadd and
                          # canonical NaN used as input, (NaN * 1) - 1 = NaN
    fmsub.s fa7, fa3, fa4, fa3
    fmsub.s fs2, fa3, fa3, fa4
   )");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xffffffff00000000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);
  EXPECT_EQ(getFPRegister<uint64_t>(17), boxedPositiveNan);
  EXPECT_EQ(getFPRegister<uint64_t>(18), boxedPositiveNan);

  EXPECT_GROUP(R"(fmsub.s fa7, fa4, fa3, fa5)", FLOAT_MUL);
}

TEST_P(InstFloat, FMSUB_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)

    fmsub.d fa6, fa5, fa4, fa3 # (999.212341 * -3.78900003) - 4.52432537
    fmsub.d fa7, fa4, fa3, fa5
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(15), (double)999.212341);
  EXPECT_EQ(getFPRegister<double>(16),
            ((double)999.212341 * (double)-3.78900003) - (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(16),
            (double)-3790.5399153953703716979362070560455322265625);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0xC0AD9D146FCA6B72);
  EXPECT_EQ(getFPRegister<uint64_t>(17), 0xC08FC2D70F769B06);

  EXPECT_GROUP(R"(fmsub.d fa7, fa4, fa3, fa5)", FLOAT_MUL);
}

TEST_P(InstFloat, FNMADD_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)

    fnmadd.s fa6, fa5, fa4, fa3 # -(999.212341 * -3.78900003) - 4.52432537
    fnmadd.s fa7, fa4, fa3, fa5
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);
  EXPECT_EQ(getFPRegister<float>(16),
            -((float)999.212341 * (float)-3.78900003) - (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(16), (float)3781.4912646554);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0xFFFFFFFF456c57dc);
  EXPECT_EQ(getFPRegister<uint64_t>(17), 0xFFFFFFFFc4758476);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fnmadd.s fa5, fa3, fa3, fa3  # -(1 * 1) - 1 = -2
    fnmadd.s fa6, fa4, fa3, fa3  # Incorrect NaN box should be caught by fmadd and
                          # canonical NaN used as input, -(NaN * 1) - 1 = NaN
    fnmadd.s fa7, fa3, fa4, fa3
    fnmadd.s fs2, fa3, fa3, fa4
   )");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xffffffffc0000000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);
  EXPECT_EQ(getFPRegister<uint64_t>(17), boxedPositiveNan);
  EXPECT_EQ(getFPRegister<uint64_t>(18), boxedPositiveNan);

  EXPECT_GROUP(R"(fnmadd.s fa7, fa4, fa3, fa5)", FLOAT_MUL);
}

TEST_P(InstFloat, FNMADD_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
     # Get heap address
     li a7, 214
     ecall

     fld fa3, 0(a0)
     fld fa5, 8(a0)
     fld fa4, 16(a0)

     fnmadd.d fa6, fa5, fa4, fa3 # -(999.212341 * -3.78900003) - 4.52432537
     fnmadd.d fa7, fa4, fa3, fa5
    )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(15), (double)999.212341);
  EXPECT_EQ(getFPRegister<double>(16),
            -((double)999.212341 * (double)-3.78900003) - (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(16),
            (double)3781.4912646553702870733104646205902099609375);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0x40AD8AFB870A78FE);
  EXPECT_EQ(getFPRegister<uint64_t>(17), 0xC08EB08EB0368E94);

  EXPECT_GROUP(R"(fnmadd.d fa6, fa5, fa4, fa3)", FLOAT_MUL);
}

TEST_P(InstFloat, FCVT_D_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)

    fcvt.d.s ft0, fa3
    fcvt.d.s ft1, fa4
    fcvt.d.s ft2, fa5
   )");

  // Floats should be NaN boxed within 64 bit floating point registers
  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff4090c746);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xffffffffc0727efa);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);
  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xffffffff4479cd97);

  // Must cast to float then to double to account for representation errors.
  // Can't directly cast to double
  EXPECT_EQ(getFPRegister<double>(0), (double)(float)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0x401218E8C0000000);
  EXPECT_EQ(getFPRegister<double>(1), (double)(float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xC00E4FDF40000000);
  EXPECT_EQ(getFPRegister<double>(2), (double)(float)999.212341);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0x408F39B2E0000000);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fcvt.d.s ft0, fa3 # fcvt 1 = 1
    fcvt.d.s ft1, fa4 # Incorrect NaN box should be caught by fcvt and
                          # canonical NaN used as input, fcvt NaN = 2^32 − 1
)");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(0), 0x3FF0000000000000);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0x7FF8000000000000);

  EXPECT_GROUP(R"(fcvt.d.s ft0, fa3)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FCVT_S_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)

    fcvt.s.d ft0, fa3
    fcvt.s.d ft1, fa4
    fcvt.s.d ft2, fa5
   )");

  // Floats should be NaN boxed within 64 bit floating point registers
  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(13), 0x401218E8BFF273D0);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xC00E4FDF3F6B24E7);
  EXPECT_EQ(getFPRegister<double>(15), (double)999.212341);
  EXPECT_EQ(getFPRegister<uint64_t>(15), 0x408F39B2DFD694CD);

  EXPECT_EQ(getFPRegister<float>(0), (float)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xFFFFFFFF4090c746);
  EXPECT_EQ(getFPRegister<float>(1), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xFFFFFFFFc0727efa);
  EXPECT_EQ(getFPRegister<float>(2), (float)999.212341);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xFFFFFFFF4479cd97);

  EXPECT_GROUP(R"(fcvt.s.d ft0, fa3)", FLOAT_SIMPLE_CVT);
}

TEST_P(InstFloat, FSGNJ_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)

    fsgnj.d fa6, fa4, fa5
    fsgnj.d fa7, fa4, fa4
    fsgnj.d ft0, fa5, fa4
    fsgnj.d ft1, fa5, fa5
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(15), (double)999.212341);
  EXPECT_EQ(getFPRegister<double>(16), (double)3.78900003);
  EXPECT_EQ(getFPRegister<double>(17), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(0), (double)-999.212341);
  EXPECT_EQ(getFPRegister<double>(1), (double)999.212341);

  // Pseudoinstructions fmv.d

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa4, 16(a0)

    fmv.d ft2, fa4
    fmv.d ft3, fa3
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(2), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(3), (double)4.52432537);

  EXPECT_GROUP(R"(fsgnj.d fa6, fa4, fa5)", FLOAT_SIMPLE_LOGICAL);
  EXPECT_GROUP(R"(fmv.d ft2, fa4)", FLOAT_SIMPLE_LOGICAL);
}

TEST_P(InstFloat, FSGNJ_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)

    fsgnj.s fa6, fa4, fa5
    fsgnj.s fa7, fa4, fa4
    fsgnj.s ft0, fa5, fa4
    fsgnj.s ft1, fa5, fa5
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);
  EXPECT_EQ(getFPRegister<float>(16), (float)3.78900003);
  EXPECT_EQ(getFPRegister<float>(17), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(0), (float)-999.212341);
  EXPECT_EQ(getFPRegister<float>(1), (float)999.212341);

  // Pseudoinstructions fmv.s

  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      flw fa3, 0(a0)
      flw fa4, 8(a0)

      fmv.s ft2, fa4
      fmv.s ft3, fa3
     )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(2), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xFFFFFFFFc0727efa);
  EXPECT_EQ(getFPRegister<float>(3), (float)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(3), 0xFFFFFFFF4090c746);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffffbf800000;  // Correct NaN boxing of no. -1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fsgnj.s ft0, fa3, fa3 # fsgnj -1, -1 = -1
    fsgnj.s ft1, fa4, fa3 # Incorrect NaN box should be caught by fsgnj and
                          # canonical NaN used as input, fsgnj +NaN, -1 = -NaN
    fsgnj.s ft2, fa3, fa4 # Not commutative, fsgnj -1, +NaN = 1
)");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffffbf800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xffffffffbf800000);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xffffffffffc00000);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xffffffff3f800000);

  EXPECT_GROUP(R"(fsgnj.s fa6, fa4, fa5)", FLOAT_SIMPLE_LOGICAL);
  EXPECT_GROUP(R"(fmv.s ft2, fa4)", FLOAT_SIMPLE_LOGICAL);
}

TEST_P(InstFloat, FSGNJX_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)

    fsgnjx.d fa6, fa4, fa5
    fsgnjx.d fa7, fa4, fa4
    fsgnjx.d ft0, fa5, fa4
    fsgnjx.d ft1, fa5, fa5
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(15), (double)999.212341);
  EXPECT_EQ(getFPRegister<double>(16), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(17), (double)3.78900003);
  EXPECT_EQ(getFPRegister<double>(0), (double)-999.212341);
  EXPECT_EQ(getFPRegister<double>(1), (double)999.212341);

  //   Pseudoinstructions fabs.d

  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      fld fa3, 0(a0)
      fld fa4, 16(a0)

      fabs.d ft2, fa4
      fabs.d ft3, fa3
     )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(2), (double)3.78900003);
  EXPECT_EQ(getFPRegister<double>(3), (double)4.52432537);

  EXPECT_GROUP(R"(fsgnjx.d fa6, fa4, fa5)", FLOAT_SIMPLE_LOGICAL);
  EXPECT_GROUP(R"(fabs.d ft2, fa4)", FLOAT_SIMPLE_LOGICAL);
}

TEST_P(InstFloat, FSGNJX_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)

    fsgnjx.s fa6, fa4, fa5
    fsgnjx.s fa7, fa4, fa4
    fsgnjx.s ft0, fa5, fa4
    fsgnjx.s ft1, fa5, fa5
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);
  EXPECT_EQ(getFPRegister<float>(16), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(17), (float)3.78900003);
  EXPECT_EQ(getFPRegister<float>(0), (float)-999.212341);
  EXPECT_EQ(getFPRegister<float>(1), (float)999.212341);

  //   Pseudoinstructions fabs.s

  RUN_RISCV(R"(
        # Get heap address
        li a7, 214
        ecall

        flw fa3, 0(a0)
        flw fa4, 8(a0)

        fabs.s ft2, fa4
        fabs.s ft3, fa3
       )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(2), (float)3.78900003);
  EXPECT_EQ(getFPRegister<float>(3), (float)4.52432537);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffffbf800000;  // Correct NaN boxing of no. -1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fsgnjx.s ft0, fa3, fa3 # fsgnjx -1, -1 = 1
    fsgnjx.s ft1, fa4, fa3 # Incorrect NaN box should be caught by fsgnjx and
                          # canonical NaN used as input, fsgnjx +NaN, -1 = -NaN
    fsgnjx.s ft2, fa3, fa4 # Not commutative, fsgnjx -1, +NaN = -1
)");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffffbf800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xffffffffffc00000);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xffffffffbf800000);

  EXPECT_GROUP(R"(fsgnjx.s fa6, fa4, fa5)", FLOAT_SIMPLE_LOGICAL);
  EXPECT_GROUP(R"(fabs.s ft2, fa4)", FLOAT_SIMPLE_LOGICAL);
}

TEST_P(InstFloat, FSGNJN_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)

    fsgnjn.d fa6, fa4, fa5
    fsgnjn.d fa7, fa4, fa4
    fsgnjn.d ft0, fa5, fa4
    fsgnjn.d ft1, fa5, fa5
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(15), (double)999.212341);

  EXPECT_EQ(getFPRegister<double>(16), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(17), (double)3.78900003);
  EXPECT_EQ(getFPRegister<double>(0), (double)999.212341);
  EXPECT_EQ(getFPRegister<double>(1), (double)-999.212341);

  //   Pseudoinstructions fneg.d

  RUN_RISCV(R"(
        # Get heap address
        li a7, 214
        ecall

        fld fa3, 0(a0)
        fld fa4, 16(a0)

        fneg.d ft2, fa4
        fneg.d ft3, fa3
       )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(2), (double)3.78900003);
  EXPECT_EQ(getFPRegister<double>(3), (double)-4.52432537);

  EXPECT_GROUP(R"(fsgnjn.d fa6, fa4, fa5)", FLOAT_SIMPLE_LOGICAL);
  EXPECT_GROUP(R"(fneg.d ft2, fa4)", FLOAT_SIMPLE_LOGICAL);
}

TEST_P(InstFloat, FSGNJN_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)

    fsgnjn.s fa6, fa4, fa5
    fsgnjn.s fa7, fa4, fa4
    fsgnjn.s ft0, fa5, fa4
    fsgnjn.s ft1, fa5, fa5
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);

  EXPECT_EQ(getFPRegister<float>(16), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(17), (float)3.78900003);
  EXPECT_EQ(getFPRegister<float>(0), (float)999.212341);
  EXPECT_EQ(getFPRegister<float>(1), (float)-999.212341);

  //   Pseudoinstructions fneg.s

  RUN_RISCV(R"(
        # Get heap address
        li a7, 214
        ecall

        flw fa3, 0(a0)
        flw fa4, 8(a0)

        fneg.s ft2, fa4
        fneg.s ft3, fa3
       )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(2), (float)3.78900003);
  EXPECT_EQ(getFPRegister<float>(3), (float)-4.52432537);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffffbf800000;  // Correct NaN boxing of no. -1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fsgnjn.s ft0, fa3, fa3 # fsgnjn -1, -1 = 1
    fsgnjn.s ft1, fa4, fa3 # Incorrect NaN box should be caught by fsgnjn and
                          # canonical NaN used as input, fsgnjn +NaN, -1 = NaN
    fsgnjn.s ft2, fa3, fa4 # Not commutative, fsgnjn -1, +NaN = -1
)");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffffbf800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(1), boxedPositiveNan);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xffffffffbf800000);

  EXPECT_GROUP(R"(fsgnjn.s fa6, fa4, fa5)", FLOAT_SIMPLE_LOGICAL);
  EXPECT_GROUP(R"(fneg.s ft2, fa4)", FLOAT_SIMPLE_LOGICAL);
}

TEST_P(InstFloat, FADD_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)

    fadd.s ft0, fa4, fa3
    fadd.s ft1, fa5, fa4
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);

  EXPECT_EQ(getFPRegister<float>(0), (float)0.73532534);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xFFFFFFFF3f3c3e48);
  EXPECT_EQ(getFPRegister<float>(1), (float)995.423341);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xFFFFFFFF4478db18);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fadd.s fa5, fa3, fa3  # 1 + 1 = 1
    fadd.s fa6, fa4, fa3  # Incorrect NaN box should be caught by fadd and
                          # canonical NaN used as input, NaN + 1 = NaN
   )");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xffffffff40000000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_GROUP(R"(fadd.s ft0, fa4, fa3)", FLOAT_SIMPLE_ARTH);
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

  EXPECT_GROUP(R"(fadd.d ft4, ft0, ft1)", FLOAT_SIMPLE_ARTH);
}

TEST_P(InstFloat, FSUB_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)

    fsub.d ft0, fa4, fa3
    fsub.d ft1, fa3, fa4
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(15), (double)999.212341);

  EXPECT_EQ(getFPRegister<double>(0), (double)-8.3133254);
  EXPECT_EQ(getFPRegister<double>(1), (double)8.3133254);

  EXPECT_GROUP(R"(fsub.d ft0, fa4, fa3)", FLOAT_SIMPLE_ARTH);
}

TEST_P(InstFloat, FSUB_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)

    fsub.s ft0, fa4, fa3
    fsub.s ft1, fa3, fa4
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);

  EXPECT_EQ(getFPRegister<float>(0), (float)-3.78900003 - (float)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xFFFFFFFFc1050362);
  EXPECT_EQ(getFPRegister<float>(1), (float)4.52432537 - (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xFFFFFFFF41050362);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fsub.s fa5, fa3, fa3  # 1 - 1 = 0
    fsub.s fa6, fa4, fa3  # Incorrect NaN box should be caught by fsub and
                          # canonical NaN used as input, NaN - 1 = NaN
   )");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xffffffff00000000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_GROUP(R"(fsub.s ft0, fa4, fa3)", FLOAT_SIMPLE_ARTH);
}

TEST_P(InstFloat, FSQRT_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)

    fsqrt.d ft0, fa5      # TODO set CSR = 0b1      inexact
    fsqrt.d ft1, fa4      # TODO set CSR = 0b10001  invalid op & inexact
    fdiv.d fa3, fa3, fa5  # 0.00452789199 < 0
    fsqrt.d ft2, fa3
   )");

  EXPECT_EQ(getFPRegister<double>(13), 4.52432537 / 999.212341);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(15), (double)999.212341);

  EXPECT_EQ(getFPRegister<double>(0), (double)31.6103201660470389811052882578);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0x403F9C3DF14142E6);
  EXPECT_EQ(getFPRegister<uint64_t>(1), 0x7FF8000000000000);  // NaN
  EXPECT_EQ(getFPRegister<double>(2), (double)0.067289611417595679432324118352);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0x3FB139E458662CD6);

  EXPECT_GROUP(R"(fsqrt.d ft0, fa5)", FLOAT_DIV_OR_SQRT);
}

TEST_P(InstFloat, FSQRT_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)

    fsqrt.s ft0, fa5      # TODO set CSR = 0b1      inexact
    fsqrt.s ft1, fa4      # TODO set CSR = 0b10001  invalid op & inexact
    fdiv.s fa3, fa3, fa5  # 0.00452789199 < 0
    fsqrt.s ft2, fa3
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)0.00452789199);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(15), (float)999.212341);

  EXPECT_EQ(getFPRegister<float>(0), (float)31.610321);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0xFFFFFFFF41FCE1F0);
  EXPECT_EQ(getFPRegister<uint64_t>(1), boxedPositiveNan);  // NaN
  EXPECT_EQ(getFPRegister<float>(2), (float)0.0672896132);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xFFFFFFFF3D89CF23);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fsqrt.s fa5, fa3  # 1^0.5 = 1
    fsqrt.s fa6, fa4  # Incorrect NaN box should be caught by fsqrt and
                      # canonical NaN used as input, NaN^0.5 = NaN
   )");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_GROUP(R"(fsqrt.s ft0, fa5)", FLOAT_DIV_OR_SQRT);
}

TEST_P(InstFloat, FMV_X_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa4, 16(a0)

    fmv.x.d t0, fa3
    fmv.x.d t1, fa4
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(13), 0x401218E8BFF273D0);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xC00E4FDF3F6B24E7);

  EXPECT_EQ(getGeneralRegister<double>(5), (double)4.52432537);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x401218E8BFF273D0);
  EXPECT_EQ(getGeneralRegister<double>(6), (double)-3.78900003);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xC00E4FDF3F6B24E7);

  EXPECT_GROUP(R"(fmv.x.d t0, fa3)", FLOAT_SIMPLE_ARTH);
}

TEST_P(InstFloat, FMV_X_W) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa4, 8(a0)

    fmv.x.w t0, fa3
    fmv.x.w t1, fa4
   )");

  // Floats should be NaN boxed within 64 bit floating point registers
  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff4090c746);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xffffffffc0727efa);

  // "float" should be sign extended when moved to integer register
  EXPECT_EQ(getGeneralRegister<float>(5), (float)4.52432537);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x000000004090c746);
  EXPECT_EQ(getGeneralRegister<float>(6), (float)-3.78900003);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xffffffffc0727efa);

  EXPECT_GROUP(R"(fmv.x.w t0, fa3)", FLOAT_SIMPLE_ARTH);
}

TEST_P(InstFloat, FMV_D_X) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa4, 16(a0)

    fmv.x.d t0, fa3
    fmv.x.d t1, fa4

    fmv.d.x fa4, t0
    fmv.d.x fa3, t1
   )");

  EXPECT_EQ(getFPRegister<double>(14), (double)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0x401218E8BFF273D0);
  EXPECT_EQ(getFPRegister<double>(13), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xC00E4FDF3F6B24E7);

  EXPECT_EQ(getGeneralRegister<double>(5), (double)4.52432537);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x401218E8BFF273D0);
  EXPECT_EQ(getGeneralRegister<double>(6), (double)-3.78900003);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xC00E4FDF3F6B24E7);

  EXPECT_GROUP(R"(fmv.d.x fa4, t0)", FLOAT_SIMPLE_ARTH);
}

TEST_P(InstFloat, FMV_W_X) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = 123456;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa4, 8(a0)

    fmv.x.w t0, fa3
    fmv.x.w t1, fa4

    fmv.w.x fa4, t0
    fmv.w.x fa3, t1
   )");

  EXPECT_EQ(getFPRegister<float>(14), (float)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xFFFFFFFF4090c746);
  EXPECT_EQ(getFPRegister<float>(13), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffffc0727efa);

  EXPECT_EQ(getGeneralRegister<float>(5), (float)4.52432537);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x000000004090c746);
  EXPECT_EQ(getGeneralRegister<float>(6), (float)-3.78900003);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xffffffffc0727efa);

  EXPECT_GROUP(R"(fmv.w.x fa4, t0)", FLOAT_SIMPLE_ARTH);
}

TEST_P(InstFloat, FEQ_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)
    fld fa6, 24(a0)

    feq.d t0, fa3, fa3 #equal set t0
    feq.d t1, fa3, fa4 #unequal don't set t1
    feq.d t2, fa6, fa4 #one NaN don't set t2
    feq.d t3, fa6, fa6 #both NaN don't set t3
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0x7FF8000000000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);

  EXPECT_GROUP(R"(feq.d t0, fa3, fa3)", FLOAT_SIMPLE_CMP);
}

TEST_P(InstFloat, FEQ_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)
    flw fa6, 12(a0)

    feq.s t0, fa3, fa3 #equal set t0
    feq.s t1, fa3, fa4 #unequal don't set t1
    feq.s t2, fa6, fa4 #one NaN don't set t2
    feq.s t3, fa6, fa6 #both NaN don't set t3
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffffbf800000;  // Correct NaN boxing of no. -1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    feq.s t0, fa3, fa3 # feq -1, -1 = 1
    feq.s t1, fa4, fa3 # Incorrect NaN box should be caught by feq and
                          # canonical NaN used as input, feq NaN, 1 = 0
)");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffffbf800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x0);

  EXPECT_GROUP(R"(feq.s t0, fa3, fa3)", FLOAT_SIMPLE_CMP);
}

TEST_P(InstFloat, FLT_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)
    fld fa6, 24(a0)

    flt.d t0, fa3, fa3 #equal don't set t0
    flt.d t1, fa3, fa4 #fa3 </ fa4 don't set t1
    flt.d t4, fa4, fa3 #fa4 < fa3 set t4
    flt.d t2, fa6, fa4 #one NaN don't set t2
    flt.d t3, fa6, fa6 #both NaN don't set t3
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0x7FF8000000000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 1);

  EXPECT_GROUP(R"(flt.d t0, fa3, fa3)", FLOAT_SIMPLE_CMP);
}

TEST_P(InstFloat, FLT_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)
    flw fa6, 12(a0)

    flt.s t0, fa3, fa3 #equal don't set t0
    flt.s t1, fa3, fa4 #fa3 </ fa4 don't set t1
    flt.s t4, fa4, fa3 #fa4 < fa3 set t4
    flt.s t2, fa6, fa4 #one NaN don't set t2
    flt.s t3, fa6, fa6 #both NaN don't set t3
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 1);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffffbf800000;  // Correct NaN boxing of no. -1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    flt.s t0, fa3, fa3 # flt -1, -1 = 0
    flt.s t1, fa4, fa3 # Incorrect NaN box should be caught by flt and
                          # canonical NaN used as input, flt NaN, 1 = 0
)");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffffbf800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x0);

  EXPECT_GROUP(R"(flt.s t0, fa3, fa3)", FLOAT_SIMPLE_CMP);
}

TEST_P(InstFloat, FLE_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)
    fld fa6, 24(a0)

    fle.d t0, fa3, fa3 #equal set t0
    fle.d t1, fa3, fa4 #fa3 <=/ fa4 don't set t1
    fle.d t4, fa4, fa3 #fa4 < fa3 set t4
    fle.d t2, fa6, fa4 #one NaN don't set t2
    fle.d t3, fa6, fa6 #both NaN don't set t3
   )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0x7FF8000000000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 1);

  EXPECT_GROUP(R"(fle.d t0, fa3, fa3)", FLOAT_SIMPLE_CMP);
}

TEST_P(InstFloat, FLE_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)
    flw fa6, 12(a0)

    fle.s t0, fa3, fa3 #equal set t0
    fle.s t1, fa3, fa4 #fa3 <=/ fa4 don't set t1
    fle.s t4, fa4, fa3 #fa4 < fa3 set t4
    fle.s t2, fa6, fa4 #one NaN don't set t2
    fle.s t3, fa6, fa6 #both NaN don't set t3
   )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 1);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffffbf800000;  // Correct NaN boxing of no. -1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fle.s t0, fa3, fa3 # fle -1, -1 = 1
    fle.s t1, fa4, fa3 # Incorrect NaN box should be caught by fle and
                          # canonical NaN used as input, fle NaN, 1 = 0
)");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffffbf800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x0);

  EXPECT_GROUP(R"(fle.s t0, fa3, fa3)", FLOAT_SIMPLE_CMP);
}

TEST_P(InstFloat, FMIN_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)
    fld fa6, 24(a0)

    fmin.d fa0, fa3, fa4
    fmin.d fa1, fa3, fa6 # min(n, NaN) = n
    fmin.d ft0, fa6, fa6 # min(NaN, NaN) = NaN

    fcvt.d.l ft1, zero
    fneg.d ft2, ft1

    fmin.d ft3, ft1, ft2 # min(+0, -0) = -0
    fmin.d ft4, ft2, ft1 # min(-0, +0) = -0
  )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0x7FF8000000000000);

  EXPECT_EQ(getFPRegister<double>(10), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<double>(11), (double)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0x7FF8000000000000);
  EXPECT_EQ(getFPRegister<double>(3),
            (double)-0);  // Doesn't check for sign so below test needed
  EXPECT_EQ(getFPRegister<uint64_t>(3), 0x8000000000000000);
  EXPECT_EQ(getFPRegister<double>(4), (double)-0);
  EXPECT_EQ(getFPRegister<uint64_t>(4), 0x8000000000000000);

  EXPECT_GROUP(R"(fmin.d fa0, fa3, fa4)", FLOAT_SIMPLE_CMP);
}

TEST_P(InstFloat, FMIN_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa4, 8(a0)
    flw fa6, 12(a0)

    fmin.s fa0, fa3, fa4
    fmin.s fa1, fa3, fa6 # min(n, NaN) = n
    fmin.s ft0, fa6, fa6 # min(NaN, NaN) = NaN

    fcvt.s.w ft1, zero
    fneg.s ft2, ft1

    fmin.s ft3, ft1, ft2 # min(+0, -0) = -0 # fminf picks the later of the two options in both cases. Check our implementation fixes this to pick -0 instead
    fmin.s ft4, ft2, ft1 # min(-0, +0) = -0
  )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_EQ(getFPRegister<float>(10), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<float>(11), (float)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(0), boxedPositiveNan);

  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xffffffff00000000);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xffffffff80000000);
  EXPECT_EQ(getFPRegister<uint64_t>(3), 0xffffffff80000000);
  EXPECT_EQ(getFPRegister<uint64_t>(4), 0xffffffff80000000);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fmin.s fa5, fa3, fa3  # fmin(1, 1) = 1
    fmin.s fa6, fa4, fa4  # Incorrect NaN box should be caught by fmin and
                          # canonical NaN used as input, fmin(NaN, NaN) = NaN
   )");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_GROUP(R"(fmin.s fa0, fa3, fa4)", FLOAT_SIMPLE_CMP);
}

TEST_P(InstFloat, FMAX_D) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)
    fld fa5, 8(a0)
    fld fa4, 16(a0)
    fld fa6, 24(a0)

    fmax.d fa0, fa3, fa4
    fmax.d fa1, fa3, fa6 # max(n, NaN) = n
    fmax.d ft0, fa6, fa6 # max(NaN, NaN) = NaN

    fcvt.d.l ft1, zero
    fneg.d ft2, ft1

    fmax.d ft3, ft1, ft2 # max(+0, -0) = 0
    fmax.d ft4, ft1, ft1 # max(-0, +0) = 0
  )");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0x7FF8000000000000);

  EXPECT_EQ(getFPRegister<double>(10), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(11), (double)4.52432537);
  EXPECT_EQ(getFPRegister<uint64_t>(0), 0x7FF8000000000000);
  EXPECT_EQ(getFPRegister<double>(3), (double)0);
  EXPECT_EQ(getFPRegister<uint64_t>(3), 0x0000000000000000);
  EXPECT_EQ(getFPRegister<uint64_t>(4), 0x0000000000000000);

  EXPECT_GROUP(R"(fmax.d fa0, fa3, fa4)", FLOAT_SIMPLE_CMP);
}

TEST_P(InstFloat, FMAX_S) {
  initialHeapData_.resize(32);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 999.212341;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    flw fa3, 0(a0)
    flw fa5, 4(a0)
    flw fa4, 8(a0)
    flw fa6, 12(a0)

    fmax.s fa0, fa3, fa4
    fmax.s fa1, fa3, fa6 # max(n, NaN) = n
    fmax.s ft0, fa6, fa6 # max(NaN, NaN) = NaN

    fcvt.s.w ft1, zero
    fneg.s ft2, ft1

    fmax.s ft3, ft1, ft2 # max(+0, -0) = +0
    fmax.s ft4, ft2, ft1 # max(-0, +0) = +0
  )");

  EXPECT_EQ(getFPRegister<float>(13), (float)4.52432537);
  EXPECT_EQ(getFPRegister<float>(14), (float)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_EQ(getFPRegister<uint64_t>(10), 0xffffffff4090c746);
  EXPECT_EQ(getFPRegister<uint64_t>(11), 0xffffffff4090c746);
  EXPECT_EQ(getFPRegister<uint64_t>(0), boxedPositiveNan);

  EXPECT_EQ(getFPRegister<uint64_t>(1), 0xffffffff00000000);
  EXPECT_EQ(getFPRegister<uint64_t>(2), 0xffffffff80000000);
  EXPECT_EQ(getFPRegister<uint64_t>(3), 0xffffffff00000000);
  EXPECT_EQ(getFPRegister<uint64_t>(4), 0xffffffff00000000);

  initialHeapData_.resize(32);
  uint64_t* intHeap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  intHeap[0] = 0xffffffff3f800000;  // Correct NaN boxing of no. 1
  intHeap[1] = 0xfff7ffff3f800000;  // Incorrect NaN boxing of no. 1

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0) # Correct
    fld fa4, 8(a0) # Incorrect

    fmax.s fa5, fa3, fa3  # fmax(1, 1) = 1
    fmax.s fa6, fa4, fa4  # Incorrect NaN box should be caught by fmax and
                          # canonical NaN used as input, fmax(NaN, NaN) = NaN
   )");

  EXPECT_EQ(getFPRegister<uint64_t>(13), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(14), 0xfff7ffff3f800000);

  EXPECT_EQ(getFPRegister<uint64_t>(15), 0xffffffff3f800000);
  EXPECT_EQ(getFPRegister<uint64_t>(16), boxedPositiveNan);

  EXPECT_GROUP(R"(fmax.s fa0, fa3, fa4)", FLOAT_SIMPLE_CMP);
}

TEST_P(InstFloat, RoundToNearest) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 3.5;
  heap[1] = 2.5;
  heap[2] = -3.5;
  heap[3] = -2.5;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    # Set rounding mode to RISC-V "nearest ties to even"
    li a1, 0
    fsrm a1

    fld fa3, 0(a0)   # 3.5
    fld fa4, 8(a0)   # 2.5
    fld fa5, 16(a0)  # -3.5
    fld fa6, 24(a0)  # -2.5

    # Test for how CPP handles ties
    fcvt.w.d t0, fa3      # should convert to 4
    fcvt.w.d t1, fa4      # should convert to 2
    fcvt.w.d t2, fa5      # should convert to -4
    fcvt.w.d t3, fa6      # should convert to -2
)");

  EXPECT_EQ(getFPRegister<double>(13), (double)3.5);
  EXPECT_EQ(getFPRegister<double>(14), (double)2.5);
  EXPECT_EQ(getFPRegister<double>(15), (double)-3.5);
  EXPECT_EQ(getFPRegister<double>(16), (double)-2.5);

  // Test for CPP tie handling. Below case test for ties to even
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0xFFFFFFFFFFFFFFFC);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0xFFFFFFFFFFFFFFFE);
}

TEST_P(InstFloat, StaticRoundingMode) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 2.5;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    # Set rounding mode to "nearest ties to even"
    li a1, 0
    fsrm a1

    fld fa3, 0(a0)   # 4.52432537
    fld fa4, 8(a0)   # 2.5
    fld fa5, 16(a0)  # -3.78900003
    fld fa6, 24(a0)  # nan

    # Should obey dynamic rounding mode in CSR
    fcvt.w.d t0, fa3      # should convert to 5
    fcvt.w.d t1, fa4      # should convert to 2
    fcvt.w.d t2, fa5      # should convert to -4

    #towards zero
    fcvt.w.d t3, fa3, rtz      # should convert to 4
    fcvt.w.d t4, fa4, rtz      # should convert to 2
    fcvt.w.d t5, fa5, rtz      # should convert to -3

    #towards -inf
    fcvt.w.d t6, fa3, rdn      # should convert to 4
    fcvt.w.d a0, fa4, rdn      # should convert to 2
    fcvt.w.d a1, fa5, rdn      # should convert to -4

    #towards +inf
    fcvt.w.d a2, fa3, rup      # should convert to 5
    fcvt.w.d a3, fa4, rup      # should convert to 3
    fcvt.w.d a4, fa5, rup      # should convert to -3

    #to nearest ties to maximum magnitude
    fcvt.w.d a5, fa3, rmm      # should convert to 5
    fcvt.w.d a6, fa4, rmm      # should convert to 3
    fcvt.w.d a7, fa5, rmm      # should convert to -4


    # Set rounding mode to "round down"
    li s2, 2
    fsrm s2

    # Should obey dynamic rounding mode in CSR
    fcvt.w.d s2, fa3      # should convert to 4
    fcvt.w.d s3, fa4      # should convert to 2
    fcvt.w.d s4, fa5      # should convert to -4

    #to nearest ties to even
    fcvt.w.d s5, fa3, rne      # should convert to 5
    fcvt.w.d s6, fa4, rne      # should convert to 2
    fcvt.w.d s7, fa5, rne      # should convert to -4
)");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)2.5);
  EXPECT_EQ(getFPRegister<double>(15), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0x7FF8000000000000);

  // Dynamic
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0xFFFFFFFFFFFFFFFC);

  // RTZ
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0x2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0xFFFFFFFFFFFFFFFD);

  // RDN
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 0x2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(11), 0xFFFFFFFFFFFFFFFC);

  // RUP
  EXPECT_EQ(getGeneralRegister<uint64_t>(12), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(13), 0x3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(14), 0xFFFFFFFFFFFFFFFD);

  // RMM
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 0x5);
  // This test won't pass as CPP doesn't provide functionality to tie to max
  // magnitude
  //  EXPECT_EQ(getGeneralRegister<uint64_t>(16), 0x3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(17), 0xFFFFFFFFFFFFFFFC);

  // Dynamic change to RDN
  EXPECT_EQ(getGeneralRegister<uint64_t>(18), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(19), 0x2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(20), 0xFFFFFFFFFFFFFFFC);

  // Dynamic
  EXPECT_EQ(getGeneralRegister<uint64_t>(21), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(22), 0x2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(23), 0xFFFFFFFFFFFFFFFC);
}

TEST_P(InstFloat, DynamicRoundingMode) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 4.52432537;
  heap[1] = 2.5;
  heap[2] = -3.78900003;
  heap[3] = std::nan("0");

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    fld fa3, 0(a0)   # 4.52432537
    fld fa4, 8(a0)   # 2.5
    fld fa5, 16(a0)  # -3.78900003
    fld fa6, 24(a0)  # nan

    # Set rounding mode to RNE
    li a1, 0
    fsrm a1

    #nearest ties to even
    fcvt.w.d t0, fa3      # should convert to 5
    fcvt.w.d t1, fa4      # should convert to 2
    fcvt.w.d t2, fa5      # should convert to -4


    # Set rounding mode to RTZ
    li a1, 1
    fsrm a1

    #towards zero
    fcvt.w.d t3, fa3      # should convert to 4
    fcvt.w.d t4, fa4      # should convert to 2
    fcvt.w.d t5, fa5      # should convert to -3


    # Set rounding mode to RDN
    li a1, 2
    fsrm a1

    #towards -inf
    fcvt.w.d t6, fa3      # should convert to 4
    fcvt.w.d a0, fa4      # should convert to 2
    fcvt.w.d s7, fa5      # should convert to -4


    # Set rounding mode to RUP
    li a1, 3
    fsrm a1

    #towards +inf
    fcvt.w.d a2, fa3      # should convert to 5
    fcvt.w.d a3, fa4      # should convert to 3
    fcvt.w.d a4, fa5      # should convert to -3


    # Set rounding mode to RMM
    li a1, 4
    fsrm a1

    #to nearest ties to maximum magnitude
    fcvt.w.d a5, fa3, rmm      # should convert to 5
    fcvt.w.d a6, fa4, rmm      # should convert to 3
    fcvt.w.d a7, fa5, rmm      # should convert to -4

)");

  EXPECT_EQ(getFPRegister<double>(13), (double)4.52432537);
  EXPECT_EQ(getFPRegister<double>(14), (double)2.5);
  EXPECT_EQ(getFPRegister<double>(15), (double)-3.78900003);
  EXPECT_EQ(getFPRegister<uint64_t>(16), 0x7FF8000000000000);

  // RNE
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0xFFFFFFFFFFFFFFFC);

  // RTZ
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0x2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0xFFFFFFFFFFFFFFFD);

  // RDN
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 0x2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(23), 0xFFFFFFFFFFFFFFFC);

  // RUP
  EXPECT_EQ(getGeneralRegister<uint64_t>(12), 0x5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(13), 0x3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(14), 0xFFFFFFFFFFFFFFFD);

  // RMM
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 0x5);
  // This test won't pass as CPP doesn't provide functionality to tie to max
  // magnitude
  //  EXPECT_EQ(getGeneralRegister<uint64_t>(16), 0x3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(17), 0xFFFFFFFFFFFFFFFC);
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstFloat,
                         ::testing::Values(std::make_tuple(EMULATION, "{}")),
                         paramToString);

}  // namespace