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
}  // namespace InstructionGroups

/** The number of aarch64 instruction groups. */
#define NUM_GROUPS 72
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
      InstructionGroups::STORE_VECTOR, InstructionGroups::STORE_SVE}},
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
    {InstructionGroups::STORE_ADDRESS,
     {InstructionGroups::STORE_ADDRESS_INT,
      InstructionGroups::STORE_ADDRESS_SCALAR,
      InstructionGroups::STORE_ADDRESS_VECTOR,
      InstructionGroups::STORE_ADDRESS_SVE}},
    {InstructionGroups::STORE_DATA,
     {InstructionGroups::STORE_DATA_INT, InstructionGroups::STORE_DATA_SCALAR,
      InstructionGroups::STORE_DATA_VECTOR,
      InstructionGroups::STORE_DATA_SVE}}};

namespace ProducerGroups {
const uint16_t INT_OP = 0;
const uint16_t INT_LOAD = 1;
const uint16_t INT_STORE = 2;
const uint16_t SIMD_FP_SVE_OP = 3;
const uint16_t SIMD_FP_SVE_LOAD = 4;
const uint16_t SIMD_FP_SVE_STORE = 5;
const uint16_t PRED_OP = 6;
const uint16_t PRED_LOAD = 7;
const uint16_t PRED_STORE = 8;
const uint16_t DEFAULT = 9;
}  // namespace ProducerGroups

namespace ConsumerGroups {
const uint16_t INT_OP = 0;
const uint16_t INT_OP_NZCV = 1;
const uint16_t INT_LOAD = 2;
const uint16_t INT_STORE = 3;
const uint16_t SIMD_FP_SVE_OP = 4;
const uint16_t SIMD_FP_SVE_OP_NZCV = 5;
const uint16_t SIMD_FP_SVE_LOAD = 6;
const uint16_t SIMD_FP_SVE_STORE = 7;
const uint16_t SVE_CMP_PR = 8;
const uint16_t SVE_CMP_NZCV = 9;
const uint16_t PRED_OP = 10;
const uint16_t PRED_OP_NZCV = 11;
const uint16_t PRED_LOAD = 12;
const uint16_t PRED_STORE = 13;
const uint16_t DEFAULT = 14;
}  // namespace ConsumerGroups

/** An unordered map conataining all the allowed forwardings from instruction
 * group types.
 * Key = ProducerGroup forwarding from.
 * Value = Vector of {ConsumerGroups can forward to, latency of the
 * forwarding}.
 */
// TODO - update latencies & allowed forwardings to respect Ports. Currently,
// worst case scenatio is assumed for latency, and Port is disregarded for
// allowed forwarding.
const std::unordered_map<uint16_t, std::vector<std::pair<uint16_t, uint8_t>>>
    groupForwardings_ = {
        {ProducerGroups::INT_OP,
         {{ConsumerGroups::INT_OP, 1},
          {ConsumerGroups::INT_OP_NZCV, 1},
          {ConsumerGroups::INT_LOAD, 0},
          {ConsumerGroups::PRED_OP_NZCV, 6},
          {ConsumerGroups::SIMD_FP_SVE_OP_NZCV, 5},
          {ConsumerGroups::SVE_CMP_NZCV, 9}}},
        {ProducerGroups::INT_LOAD,
         {{ConsumerGroups::INT_OP, 1}, {ConsumerGroups::INT_LOAD, 0}}},
        {ProducerGroups::INT_STORE,
         {{ConsumerGroups::INT_OP, 1}, {ConsumerGroups::INT_LOAD, 0}}},
        {ProducerGroups::SIMD_FP_SVE_OP,
         {{ConsumerGroups::INT_OP_NZCV, 7},
          {ConsumerGroups::SIMD_FP_SVE_LOAD, 0},
          {ConsumerGroups::PRED_LOAD, 3},
          {ConsumerGroups::PRED_OP, 3},
          {ConsumerGroups::PRED_OP_NZCV, 8},
          {ConsumerGroups::SIMD_FP_SVE_OP, 0},
          {ConsumerGroups::SIMD_FP_SVE_OP_NZCV, 0},
          {ConsumerGroups::SVE_CMP_PR, 1},
          {ConsumerGroups::SVE_CMP_NZCV, 11}}},
        {ProducerGroups::SIMD_FP_SVE_LOAD,
         {{ConsumerGroups::INT_OP, 1},
          {ConsumerGroups::INT_LOAD, 0},
          {ConsumerGroups::PRED_OP, 1},
          {ConsumerGroups::PRED_LOAD, 0},
          {ConsumerGroups::SVE_CMP_PR, 2}}},
        {ProducerGroups::SIMD_FP_SVE_STORE,
         {{ConsumerGroups::INT_OP, 1},
          {ConsumerGroups::INT_LOAD, 0},
          {ConsumerGroups::PRED_OP, 1},
          {ConsumerGroups::PRED_LOAD, 0},
          {ConsumerGroups::SVE_CMP_PR, 2}}},
        {ProducerGroups::PRED_OP,
         {{ConsumerGroups::INT_OP_NZCV, 6},
          {ConsumerGroups::PRED_LOAD, 1},
          {ConsumerGroups::PRED_OP, 0},
          {ConsumerGroups::PRED_OP_NZCV, 7},
          {ConsumerGroups::SIMD_FP_SVE_OP_NZCV, 6},
          {ConsumerGroups::SVE_CMP_PR, 2},
          {ConsumerGroups::SVE_CMP_NZCV, 10}}},
        {ProducerGroups::PRED_LOAD,
         {{ConsumerGroups::INT_OP, 1}, {ConsumerGroups::INT_LOAD, 0}}},
        {ProducerGroups::PRED_STORE, {}},
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng