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
const uint16_t STORE_INT = 11;
const uint16_t FP = 12;
const uint16_t FP_SIMPLE = 13;
const uint16_t FP_SIMPLE_ARTH = 14;
const uint16_t FP_SIMPLE_ARTH_NOSHIFT = 15;
const uint16_t FP_SIMPLE_LOGICAL = 16;
const uint16_t FP_SIMPLE_LOGICAL_NOSHIFT = 17;
const uint16_t FP_SIMPLE_CMP = 18;
const uint16_t FP_SIMPLE_CVT = 19;
const uint16_t FP_MUL = 20;
const uint16_t FP_DIV_OR_SQRT = 21;
const uint16_t SCALAR = 22;
const uint16_t SCALAR_SIMPLE = 23;
const uint16_t SCALAR_SIMPLE_ARTH = 24;
const uint16_t SCALAR_SIMPLE_ARTH_NOSHIFT = 25;
const uint16_t SCALAR_SIMPLE_LOGICAL = 26;
const uint16_t SCALAR_SIMPLE_LOGICAL_NOSHIFT = 27;
const uint16_t SCALAR_SIMPLE_CMP = 28;
const uint16_t SCALAR_SIMPLE_CVT = 29;
const uint16_t SCALAR_MUL = 30;
const uint16_t SCALAR_DIV_OR_SQRT = 31;
const uint16_t LOAD_SCALAR = 32;
const uint16_t STORE_SCALAR = 33;
const uint16_t VECTOR = 34;
const uint16_t VECTOR_SIMPLE = 35;
const uint16_t VECTOR_SIMPLE_ARTH = 36;
const uint16_t VECTOR_SIMPLE_ARTH_NOSHIFT = 37;
const uint16_t VECTOR_SIMPLE_LOGICAL = 38;
const uint16_t VECTOR_SIMPLE_LOGICAL_NOSHIFT = 39;
const uint16_t VECTOR_SIMPLE_CMP = 40;
const uint16_t VECTOR_SIMPLE_CVT = 41;
const uint16_t VECTOR_MUL = 42;
const uint16_t VECTOR_DIV_OR_SQRT = 43;
const uint16_t LOAD_VECTOR = 44;
const uint16_t STORE_VECTOR = 45;
const uint16_t SVE = 46;
const uint16_t SVE_SIMPLE = 47;
const uint16_t SVE_SIMPLE_ARTH = 48;
const uint16_t SVE_SIMPLE_ARTH_NOSHIFT = 49;
const uint16_t SVE_SIMPLE_LOGICAL = 50;
const uint16_t SVE_SIMPLE_LOGICAL_NOSHIFT = 51;
const uint16_t SVE_SIMPLE_CMP = 52;
const uint16_t SVE_SIMPLE_CVT = 53;
const uint16_t SVE_MUL = 54;
const uint16_t SVE_DIV_OR_SQRT = 55;
const uint16_t LOAD_SVE = 56;
const uint16_t STORE_SVE = 57;
const uint16_t PREDICATE = 58;
const uint16_t LOAD = 59;
const uint16_t STORE = 60;
const uint16_t BRANCH = 61;
}  // namespace InstructionGroups

/** The number of aarch64 instruction groups. */
#define NUM_GROUPS 62
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
    {InstructionGroups::STORE,
     {InstructionGroups::STORE_INT, InstructionGroups::STORE_SCALAR,
      InstructionGroups::STORE_VECTOR, InstructionGroups::STORE_SVE}}};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng