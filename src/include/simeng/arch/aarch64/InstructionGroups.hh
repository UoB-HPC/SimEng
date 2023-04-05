#pragma once

#include <unordered_map>

namespace simeng {
namespace arch {
namespace aarch64 {

/** The IDs of the instruction groups for AArch64 instructions. */
namespace InstructionGroups {
static constexpr uint16_t INT = 0;
static constexpr uint16_t INT_SIMPLE = 1;
static constexpr uint16_t INT_SIMPLE_ARTH = 2;
static constexpr uint16_t INT_SIMPLE_ARTH_NOSHIFT = 3;
static constexpr uint16_t INT_SIMPLE_LOGICAL = 4;
static constexpr uint16_t INT_SIMPLE_LOGICAL_NOSHIFT = 5;
static constexpr uint16_t INT_SIMPLE_CMP = 6;
static constexpr uint16_t INT_SIMPLE_CVT = 7;
static constexpr uint16_t INT_MUL = 8;
static constexpr uint16_t INT_DIV_OR_SQRT = 9;
static constexpr uint16_t LOAD_INT = 10;
static constexpr uint16_t STORE_ADDRESS_INT = 11;
static constexpr uint16_t STORE_DATA_INT = 12;
static constexpr uint16_t STORE_INT = 13;
static constexpr uint16_t FP = 14;
static constexpr uint16_t FP_SIMPLE = 15;
static constexpr uint16_t FP_SIMPLE_ARTH = 16;
static constexpr uint16_t FP_SIMPLE_ARTH_NOSHIFT = 17;
static constexpr uint16_t FP_SIMPLE_LOGICAL = 18;
static constexpr uint16_t FP_SIMPLE_LOGICAL_NOSHIFT = 19;
static constexpr uint16_t FP_SIMPLE_CMP = 20;
static constexpr uint16_t FP_SIMPLE_CVT = 21;
static constexpr uint16_t FP_MUL = 22;
static constexpr uint16_t FP_DIV_OR_SQRT = 23;
static constexpr uint16_t SCALAR = 24;
static constexpr uint16_t SCALAR_SIMPLE = 25;
static constexpr uint16_t SCALAR_SIMPLE_ARTH = 26;
static constexpr uint16_t SCALAR_SIMPLE_ARTH_NOSHIFT = 27;
static constexpr uint16_t SCALAR_SIMPLE_LOGICAL = 28;
static constexpr uint16_t SCALAR_SIMPLE_LOGICAL_NOSHIFT = 29;
static constexpr uint16_t SCALAR_SIMPLE_CMP = 30;
static constexpr uint16_t SCALAR_SIMPLE_CVT = 31;
static constexpr uint16_t SCALAR_MUL = 32;
static constexpr uint16_t SCALAR_DIV_OR_SQRT = 33;
static constexpr uint16_t LOAD_SCALAR = 34;
static constexpr uint16_t STORE_ADDRESS_SCALAR = 35;
static constexpr uint16_t STORE_DATA_SCALAR = 36;
static constexpr uint16_t STORE_SCALAR = 37;
static constexpr uint16_t VECTOR = 38;
static constexpr uint16_t VECTOR_SIMPLE = 39;
static constexpr uint16_t VECTOR_SIMPLE_ARTH = 40;
static constexpr uint16_t VECTOR_SIMPLE_ARTH_NOSHIFT = 41;
static constexpr uint16_t VECTOR_SIMPLE_LOGICAL = 42;
static constexpr uint16_t VECTOR_SIMPLE_LOGICAL_NOSHIFT = 43;
static constexpr uint16_t VECTOR_SIMPLE_CMP = 44;
static constexpr uint16_t VECTOR_SIMPLE_CVT = 45;
static constexpr uint16_t VECTOR_MUL = 46;
static constexpr uint16_t VECTOR_DIV_OR_SQRT = 47;
static constexpr uint16_t LOAD_VECTOR = 48;
static constexpr uint16_t STORE_ADDRESS_VECTOR = 49;
static constexpr uint16_t STORE_DATA_VECTOR = 50;
static constexpr uint16_t STORE_VECTOR = 51;
static constexpr uint16_t SVE = 52;
static constexpr uint16_t SVE_SIMPLE = 53;
static constexpr uint16_t SVE_SIMPLE_ARTH = 54;
static constexpr uint16_t SVE_SIMPLE_ARTH_NOSHIFT = 55;
static constexpr uint16_t SVE_SIMPLE_LOGICAL = 56;
static constexpr uint16_t SVE_SIMPLE_LOGICAL_NOSHIFT = 57;
static constexpr uint16_t SVE_SIMPLE_CMP = 58;
static constexpr uint16_t SVE_SIMPLE_CVT = 59;
static constexpr uint16_t SVE_MUL = 60;
static constexpr uint16_t SVE_DIV_OR_SQRT = 61;
static constexpr uint16_t LOAD_SVE = 62;
static constexpr uint16_t STORE_ADDRESS_SVE = 63;
static constexpr uint16_t STORE_DATA_SVE = 64;
static constexpr uint16_t STORE_SVE = 65;
static constexpr uint16_t PREDICATE = 66;
static constexpr uint16_t LOAD = 67;
static constexpr uint16_t STORE_ADDRESS = 68;
static constexpr uint16_t STORE_DATA = 69;
static constexpr uint16_t STORE = 70;
static constexpr uint16_t BRANCH = 71;
static constexpr uint16_t SME = 72;
static constexpr uint16_t SME_SIMPLE = 73;
static constexpr uint16_t SME_SIMPLE_ARTH = 74;
static constexpr uint16_t SME_SIMPLE_ARTH_NOSHIFT = 75;
static constexpr uint16_t SME_SIMPLE_LOGICAL = 76;
static constexpr uint16_t SME_SIMPLE_LOGICAL_NOSHIFT = 77;
static constexpr uint16_t SME_SIMPLE_CMP = 78;
static constexpr uint16_t SME_SIMPLE_CVT = 79;
static constexpr uint16_t SME_MUL = 80;
static constexpr uint16_t SME_DIV_OR_SQRT = 81;
static constexpr uint16_t LOAD_SME = 82;
static constexpr uint16_t STORE_ADDRESS_SME = 83;
static constexpr uint16_t STORE_DATA_SME = 84;
static constexpr uint16_t STORE_SME = 85;
}  // namespace InstructionGroups

/** The number of aarch64 instruction groups. */
static constexpr uint8_t NUM_GROUPS = 86;

const std::unordered_map<uint16_t, std::vector<uint16_t>> groupInheritance = {
    {InstructionGroups::INT,
     {InstructionGroups::INT_SIMPLE, InstructionGroups::INT_DIV_OR_SQRT,
      InstructionGroups::INT_MUL}},
    {InstructionGroups::INT_SIMPLE,
     {InstructionGroups::INT_SIMPLE_ARTH, InstructionGroups::INT_SIMPLE_LOGICAL,
      InstructionGroups::INT_SIMPLE_CMP, InstructionGroups::INT_SIMPLE_CVT}},
    {InstructionGroups::INT_SIMPLE_ARTH,
     {InstructionGroups::INT_SIMPLE_ARTH_NOSHIFT}},
    {InstructionGroups::INT_SIMPLE_LOGICAL,
     {InstructionGroups::INT_SIMPLE_LOGICAL_NOSHIFT}},
    {InstructionGroups::FP,
     {InstructionGroups::SCALAR, InstructionGroups::VECTOR}},
    {InstructionGroups::FP_SIMPLE,
     {InstructionGroups::SCALAR_SIMPLE, InstructionGroups::VECTOR_SIMPLE}},
    {InstructionGroups::FP_SIMPLE_ARTH,
     {InstructionGroups::SCALAR_SIMPLE_ARTH,
      InstructionGroups::VECTOR_SIMPLE_ARTH}},
    {InstructionGroups::FP_SIMPLE_ARTH_NOSHIFT,
     {InstructionGroups::SCALAR_SIMPLE_ARTH_NOSHIFT,
      InstructionGroups::VECTOR_SIMPLE_ARTH_NOSHIFT}},
    {InstructionGroups::FP_SIMPLE_LOGICAL,
     {InstructionGroups::SCALAR_SIMPLE_LOGICAL,
      InstructionGroups::VECTOR_SIMPLE_LOGICAL}},
    {InstructionGroups::FP_SIMPLE_LOGICAL_NOSHIFT,
     {InstructionGroups::SCALAR_SIMPLE_LOGICAL_NOSHIFT,
      InstructionGroups::VECTOR_SIMPLE_LOGICAL_NOSHIFT}},
    {InstructionGroups::FP_SIMPLE_CMP,
     {InstructionGroups::SCALAR_SIMPLE_CMP,
      InstructionGroups::VECTOR_SIMPLE_CMP}},
    {InstructionGroups::FP_SIMPLE_CVT,
     {InstructionGroups::SCALAR_SIMPLE_CVT,
      InstructionGroups::VECTOR_SIMPLE_CVT}},
    {InstructionGroups::FP_MUL,
     {InstructionGroups::SCALAR_MUL, InstructionGroups::VECTOR_MUL}},
    {InstructionGroups::FP_DIV_OR_SQRT,
     {InstructionGroups::SCALAR_DIV_OR_SQRT,
      InstructionGroups::VECTOR_DIV_OR_SQRT}},
    {InstructionGroups::SCALAR,
     {InstructionGroups::SCALAR_SIMPLE, InstructionGroups::SCALAR_DIV_OR_SQRT,
      InstructionGroups::SCALAR_MUL}},
    {InstructionGroups::SCALAR_SIMPLE,
     {InstructionGroups::SCALAR_SIMPLE_ARTH,
      InstructionGroups::SCALAR_SIMPLE_LOGICAL,
      InstructionGroups::SCALAR_SIMPLE_CMP,
      InstructionGroups::SCALAR_SIMPLE_CVT}},
    {InstructionGroups::SCALAR_SIMPLE_ARTH,
     {InstructionGroups::SCALAR_SIMPLE_ARTH_NOSHIFT}},
    {InstructionGroups::SCALAR_SIMPLE_LOGICAL,
     {InstructionGroups::SCALAR_SIMPLE_LOGICAL_NOSHIFT}},
    {InstructionGroups::VECTOR,
     {InstructionGroups::VECTOR_SIMPLE, InstructionGroups::VECTOR_DIV_OR_SQRT,
      InstructionGroups::VECTOR_MUL}},
    {InstructionGroups::VECTOR_SIMPLE,
     {InstructionGroups::VECTOR_SIMPLE_ARTH,
      InstructionGroups::VECTOR_SIMPLE_LOGICAL,
      InstructionGroups::VECTOR_SIMPLE_CMP,
      InstructionGroups::VECTOR_SIMPLE_CVT}},
    {InstructionGroups::VECTOR_SIMPLE_ARTH,
     {InstructionGroups::VECTOR_SIMPLE_ARTH_NOSHIFT}},
    {InstructionGroups::VECTOR_SIMPLE_LOGICAL,
     {InstructionGroups::VECTOR_SIMPLE_LOGICAL_NOSHIFT}},
    {InstructionGroups::SVE,
     {InstructionGroups::SVE_SIMPLE, InstructionGroups::SVE_DIV_OR_SQRT,
      InstructionGroups::SVE_MUL}},
    {InstructionGroups::SVE_SIMPLE,
     {InstructionGroups::SVE_SIMPLE_ARTH, InstructionGroups::SVE_SIMPLE_LOGICAL,
      InstructionGroups::SVE_SIMPLE_CMP, InstructionGroups::SVE_SIMPLE_CVT}},
    {InstructionGroups::SVE_SIMPLE_ARTH,
     {InstructionGroups::SVE_SIMPLE_ARTH_NOSHIFT}},
    {InstructionGroups::SVE_SIMPLE_LOGICAL,
     {InstructionGroups::SVE_SIMPLE_LOGICAL_NOSHIFT}},
    {InstructionGroups::SME,
     {InstructionGroups::SME_SIMPLE, InstructionGroups::SME_DIV_OR_SQRT,
      InstructionGroups::SME_MUL}},
    {InstructionGroups::SME_SIMPLE,
     {InstructionGroups::SME_SIMPLE_ARTH, InstructionGroups::SME_SIMPLE_LOGICAL,
      InstructionGroups::SME_SIMPLE_CMP, InstructionGroups::SME_SIMPLE_CVT}},
    {InstructionGroups::SME_SIMPLE_ARTH,
     {InstructionGroups::SME_SIMPLE_ARTH_NOSHIFT}},
    {InstructionGroups::SME_SIMPLE_LOGICAL,
     {InstructionGroups::SME_SIMPLE_LOGICAL_NOSHIFT}},
    {InstructionGroups::LOAD,
     {InstructionGroups::LOAD_INT, InstructionGroups::LOAD_SCALAR,
      InstructionGroups::LOAD_VECTOR, InstructionGroups::LOAD_SVE,
      InstructionGroups::LOAD_SME}},
    {InstructionGroups::STORE,
     {InstructionGroups::STORE_INT, InstructionGroups::STORE_SCALAR,
      InstructionGroups::STORE_VECTOR, InstructionGroups::STORE_SVE,
      InstructionGroups::STORE_SME}},
    {InstructionGroups::STORE_INT,
     {InstructionGroups::STORE_ADDRESS_INT, InstructionGroups::STORE_DATA_INT}},
    {InstructionGroups::STORE_SCALAR,
     {InstructionGroups::STORE_ADDRESS_SCALAR,
      InstructionGroups::STORE_DATA_SCALAR}},
    {InstructionGroups::STORE_VECTOR,
     {InstructionGroups::STORE_ADDRESS_VECTOR,
      InstructionGroups::STORE_DATA_VECTOR}},
    {InstructionGroups::STORE_SVE,
     {InstructionGroups::STORE_ADDRESS_SVE, InstructionGroups::STORE_DATA_SVE}},
    {InstructionGroups::STORE_SME,
     {InstructionGroups::STORE_ADDRESS_SME, InstructionGroups::STORE_DATA_SME}},
    {InstructionGroups::STORE_ADDRESS,
     {InstructionGroups::STORE_ADDRESS_INT,
      InstructionGroups::STORE_ADDRESS_SCALAR,
      InstructionGroups::STORE_ADDRESS_VECTOR,
      InstructionGroups::STORE_ADDRESS_SVE,
      InstructionGroups::STORE_ADDRESS_SME}},
    {InstructionGroups::STORE_DATA,
     {InstructionGroups::STORE_DATA_INT, InstructionGroups::STORE_DATA_SCALAR,
      InstructionGroups::STORE_DATA_VECTOR, InstructionGroups::STORE_DATA_SVE,
      InstructionGroups::STORE_DATA_SME}}};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng