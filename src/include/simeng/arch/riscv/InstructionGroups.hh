#include <unordered_map>

namespace simeng {
namespace arch {
namespace riscv {

/** The IDs of the instruction groups for RISC-V instructions. */
namespace InstructionGroups {
const uint16_t INT = 0;
const uint16_t INT_SIMPLE = 1;
const uint16_t INT_SIMPLE_ARTH = 2;
const uint16_t INT_SIMPLE_CMP = 3;
const uint16_t INT_SIMPLE_LOGICAL = 4;
const uint16_t INT_SIMPLE_SHIFT = 5;
const uint16_t INT_MUL = 6;
const uint16_t INT_DIV_OR_SQRT = 7;
const uint16_t LOAD_INT = 8;
const uint16_t STORE_INT = 9;
const uint16_t FLOAT = 10;
const uint16_t FLOAT_SIMPLE = 11;
const uint16_t FLOAT_SIMPLE_ARTH = 12;
const uint16_t FLOAT_SIMPLE_CMP = 13;
const uint16_t FLOAT_SIMPLE_LOGICAL = 14;
const uint16_t FLOAT_SIMPLE_CVT = 15;
const uint16_t FLOAT_MUL = 16;
const uint16_t FLOAT_DIV_OR_SQRT = 17;
const uint16_t LOAD_FLOAT = 18;
const uint16_t STORE_FLOAT = 19;
const uint16_t LOAD = 20;
const uint16_t STORE = 21;
const uint16_t BRANCH = 22;
}  // namespace InstructionGroups

#define NUM_GROUPS 23

const std::unordered_map<uint16_t, std::vector<uint16_t>> groupInheritance = {
    {InstructionGroups::INT,
     {InstructionGroups::INT_SIMPLE, InstructionGroups::INT_MUL,
      InstructionGroups::INT_DIV_OR_SQRT}},
    {InstructionGroups::INT_SIMPLE,
     {InstructionGroups::INT_SIMPLE_ARTH, InstructionGroups::INT_SIMPLE_CMP,
      InstructionGroups::INT_SIMPLE_LOGICAL,
      InstructionGroups::INT_SIMPLE_SHIFT}},
    {InstructionGroups::LOAD,
     {InstructionGroups::LOAD_INT, InstructionGroups::LOAD_FLOAT}},
    {InstructionGroups::STORE,
     {InstructionGroups::STORE_INT, InstructionGroups::STORE_FLOAT}},
    {InstructionGroups::FLOAT,
     {InstructionGroups::FLOAT_SIMPLE, InstructionGroups::FLOAT_MUL,
      InstructionGroups::FLOAT_DIV_OR_SQRT}},
    {InstructionGroups::FLOAT_SIMPLE,
     {InstructionGroups::FLOAT_SIMPLE_ARTH,
      InstructionGroups::FLOAT_SIMPLE_LOGICAL,
      InstructionGroups::FLOAT_SIMPLE_CMP,
      InstructionGroups::FLOAT_SIMPLE_CVT}}};

}  // namespace riscv
}  // namespace arch
}  // namespace simeng