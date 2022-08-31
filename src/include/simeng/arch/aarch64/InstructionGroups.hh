#include <unordered_map>

namespace simeng {
namespace arch {
namespace aarch64 {

/** The IDs of the instruction groups for AArch64 instructions. */
namespace InstructionGroups {
const uint16_t INT = 0;
const uint16_t INT_SIMPLE = 1;
const uint16_t INT_SIMPLE_ARTH = 2;
const uint16_t INT_SIMPLE_ARTH_NOSHIFT = 3;
const uint16_t INT_SIMPLE_LOGICAL = 4;
const uint16_t INT_SIMPLE_LOGICAL_NOSHIFT = 5;
const uint16_t INT_SIMPLE_CMP = 6;
const uint16_t INT_SIMPLE_CVT = 7;
const uint16_t INT_MUL = 8;
const uint16_t INT_DIV_OR_SQRT = 9;
const uint16_t LOAD_INT = 10;
const uint16_t STORE_ADDRESS_INT = 11;
const uint16_t STORE_DATA_INT = 12;
const uint16_t STORE_INT = 13;
const uint16_t FP = 14;
const uint16_t FP_SIMPLE = 15;
const uint16_t FP_SIMPLE_ARTH = 16;
const uint16_t FP_SIMPLE_ARTH_NOSHIFT = 17;
const uint16_t FP_SIMPLE_LOGICAL = 18;
const uint16_t FP_SIMPLE_LOGICAL_NOSHIFT = 19;
const uint16_t FP_SIMPLE_CMP = 20;
const uint16_t FP_SIMPLE_CVT = 21;
const uint16_t FP_MUL = 22;
const uint16_t FP_DIV_OR_SQRT = 23;
const uint16_t SCALAR = 24;
const uint16_t SCALAR_SIMPLE = 25;
const uint16_t SCALAR_SIMPLE_ARTH = 26;
const uint16_t SCALAR_SIMPLE_ARTH_NOSHIFT = 27;
const uint16_t SCALAR_SIMPLE_LOGICAL = 28;
const uint16_t SCALAR_SIMPLE_LOGICAL_NOSHIFT = 29;
const uint16_t SCALAR_SIMPLE_CMP = 30;
const uint16_t SCALAR_SIMPLE_CVT = 31;
const uint16_t SCALAR_MUL = 32;
const uint16_t SCALAR_DIV_OR_SQRT = 33;
const uint16_t LOAD_SCALAR = 34;
const uint16_t STORE_ADDRESS_SCALAR = 35;
const uint16_t STORE_DATA_SCALAR = 36;
const uint16_t STORE_SCALAR = 37;
const uint16_t VECTOR = 38;
const uint16_t VECTOR_SIMPLE = 39;
const uint16_t VECTOR_SIMPLE_ARTH = 40;
const uint16_t VECTOR_SIMPLE_ARTH_NOSHIFT = 41;
const uint16_t VECTOR_SIMPLE_LOGICAL = 42;
const uint16_t VECTOR_SIMPLE_LOGICAL_NOSHIFT = 43;
const uint16_t VECTOR_SIMPLE_CMP = 44;
const uint16_t VECTOR_SIMPLE_CVT = 45;
const uint16_t VECTOR_MUL = 46;
const uint16_t VECTOR_DIV_OR_SQRT = 47;
const uint16_t LOAD_VECTOR = 48;
const uint16_t STORE_ADDRESS_VECTOR = 49;
const uint16_t STORE_DATA_VECTOR = 50;
const uint16_t STORE_VECTOR = 51;
const uint16_t SVE = 52;
const uint16_t SVE_SIMPLE = 53;
const uint16_t SVE_SIMPLE_ARTH = 54;
const uint16_t SVE_SIMPLE_ARTH_NOSHIFT = 55;
const uint16_t SVE_SIMPLE_LOGICAL = 56;
const uint16_t SVE_SIMPLE_LOGICAL_NOSHIFT = 57;
const uint16_t SVE_SIMPLE_CMP = 58;
const uint16_t SVE_SIMPLE_CVT = 59;
const uint16_t SVE_MUL = 60;
const uint16_t SVE_DIV_OR_SQRT = 61;
const uint16_t LOAD_SVE = 62;
const uint16_t STORE_ADDRESS_SVE = 63;
const uint16_t STORE_DATA_SVE = 64;
const uint16_t STORE_SVE = 65;
const uint16_t PREDICATE = 66;
const uint16_t LOAD = 67;
const uint16_t STORE_ADDRESS = 68;
const uint16_t STORE_DATA = 69;
const uint16_t STORE = 70;
const uint16_t BRANCH = 71;
const uint16_t SME = 72;
const uint16_t SME_SIMPLE = 73;
const uint16_t SME_SIMPLE_ARTH = 74;
const uint16_t SME_SIMPLE_ARTH_NOSHIFT = 75;
const uint16_t SME_SIMPLE_LOGICAL = 76;
const uint16_t SME_SIMPLE_LOGICAL_NOSHIFT = 77;
const uint16_t SME_SIMPLE_CMP = 78;
const uint16_t SME_SIMPLE_CVT = 79;
const uint16_t SME_MUL = 80;
const uint16_t SME_DIV_OR_SQRT = 81;
const uint16_t LOAD_SME = 82;
const uint16_t STORE_ADDRESS_SME = 83;
const uint16_t STORE_DATA_SME = 84;
const uint16_t STORE_SME = 85;
}  // namespace InstructionGroups

/** The number of aarch64 instruction groups. */
#define NUM_GROUPS 74
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