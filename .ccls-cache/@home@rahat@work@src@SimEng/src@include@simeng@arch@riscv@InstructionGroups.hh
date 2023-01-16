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
const uint16_t INT_DIV = 7;
const uint16_t LOAD_INT = 8;
const uint16_t STORE_INT = 9;
const uint16_t LOAD = 10;
const uint16_t STORE = 11;
const uint16_t BRANCH = 12;
}  // namespace InstructionGroups

#define NUM_GROUPS 13

const std::unordered_map<uint16_t, std::vector<uint16_t>> groupInheritance = {
    {InstructionGroups::INT,
     {InstructionGroups::INT_SIMPLE, InstructionGroups::INT_MUL,
      InstructionGroups::INT_DIV}},
    {InstructionGroups::INT_SIMPLE,
     {InstructionGroups::INT_SIMPLE_ARTH, InstructionGroups::INT_SIMPLE_CMP,
      InstructionGroups::INT_SIMPLE_LOGICAL,
      InstructionGroups::INT_SIMPLE_SHIFT}},
    {InstructionGroups::LOAD, {InstructionGroups::LOAD_INT}},
    {InstructionGroups::STORE, {InstructionGroups::STORE_INT}}};

}  // namespace riscv
}  // namespace arch
}  // namespace simeng