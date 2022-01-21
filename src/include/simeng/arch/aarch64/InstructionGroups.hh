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
const uint16_t FP = 13;
const uint16_t FP_SIMPLE = 14;
const uint16_t FP_SIMPLE_ARTH = 15;
const uint16_t FP_SIMPLE_ARTH_NOSHIFT = 16;
const uint16_t FP_SIMPLE_LOGICAL = 17;
const uint16_t FP_SIMPLE_LOGICAL_NOSHIFT = 18;
const uint16_t FP_SIMPLE_CMP = 19;
const uint16_t FP_SIMPLE_CVT = 20;
const uint16_t FP_MUL = 21;
const uint16_t FP_DIV_OR_SQRT = 22;
const uint16_t SCALAR = 23;
const uint16_t SCALAR_SIMPLE = 24;
const uint16_t SCALAR_SIMPLE_ARTH = 25;
const uint16_t SCALAR_SIMPLE_ARTH_NOSHIFT = 26;
const uint16_t SCALAR_SIMPLE_LOGICAL = 27;
const uint16_t SCALAR_SIMPLE_LOGICAL_NOSHIFT = 28;
const uint16_t SCALAR_SIMPLE_CMP = 29;
const uint16_t SCALAR_SIMPLE_CVT = 30;
const uint16_t SCALAR_MUL = 31;
const uint16_t SCALAR_DIV_OR_SQRT = 32;
const uint16_t LOAD_SCALAR = 33;
const uint16_t STORE_ADDRESS_SCALAR = 34;
const uint16_t STORE_DATA_SCALAR = 35;
const uint16_t VECTOR = 36;
const uint16_t VECTOR_SIMPLE = 37;
const uint16_t VECTOR_SIMPLE_ARTH = 38;
const uint16_t VECTOR_SIMPLE_ARTH_NOSHIFT = 39;
const uint16_t VECTOR_SIMPLE_LOGICAL = 40;
const uint16_t VECTOR_SIMPLE_LOGICAL_NOSHIFT = 41;
const uint16_t VECTOR_SIMPLE_CMP = 42;
const uint16_t VECTOR_SIMPLE_CVT = 43;
const uint16_t VECTOR_MUL = 44;
const uint16_t VECTOR_DIV_OR_SQRT = 45;
const uint16_t LOAD_VECTOR = 46;
const uint16_t STORE_ADDRESS_VECTOR = 47;
const uint16_t STORE_DATA_VECTOR = 48;
const uint16_t SVE = 49;
const uint16_t SVE_SIMPLE = 50;
const uint16_t SVE_SIMPLE_ARTH = 51;
const uint16_t SVE_SIMPLE_ARTH_NOSHIFT = 52;
const uint16_t SVE_SIMPLE_LOGICAL = 53;
const uint16_t SVE_SIMPLE_LOGICAL_NOSHIFT = 54;
const uint16_t SVE_SIMPLE_CMP = 55;
const uint16_t SVE_SIMPLE_CVT = 56;
const uint16_t SVE_MUL = 57;
const uint16_t SVE_DIV_OR_SQRT = 58;
const uint16_t LOAD_SVE = 59;
const uint16_t STORE_ADDRESS_SVE = 60;
const uint16_t STORE_DATA_SVE = 61;
const uint16_t PREDICATE = 62;
const uint16_t LOAD = 63;
const uint16_t STORE_ADDRESS = 64;
const uint16_t STORE_DATA = 65;
const uint16_t BRANCH = 66;
}  // namespace InstructionGroups

/** The number of aarch64 instruction groups. */
#define NUM_GROUPS 67
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
    {InstructionGroups::LOAD,
     {InstructionGroups::LOAD_INT, InstructionGroups::LOAD_SCALAR,
      InstructionGroups::LOAD_VECTOR, InstructionGroups::LOAD_SVE}},
    {InstructionGroups::STORE_ADDRESS,
     {InstructionGroups::STORE_ADDRESS_INT,
      InstructionGroups::STORE_ADDRESS_SCALAR,
      InstructionGroups::STORE_ADDRESS_VECTOR,
      InstructionGroups::STORE_ADDRESS_SVE}},
    {InstructionGroups::STORE_DATA,
     {InstructionGroups::STORE_DATA_INT, InstructionGroups::STORE_DATA_SCALAR,
      InstructionGroups::STORE_DATA_VECTOR,
      InstructionGroups::STORE_DATA_SVE}}};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng