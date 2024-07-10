#pragma once

#include <map>

#include "simeng/Register.hh"
#include "simeng/span.hh"

namespace simeng {

/** A struct to define a consumer instruction. */
struct bypassConsumer {
  uint16_t group = 0;
  uint64_t latency = 0;
};

/** A simple class to hold the permitted operand bypass model and easily find
   the bypass latency between two instructions. */
class OperandBypassMap {
 public:
  OperandBypassMap() {}
  virtual ~OperandBypassMap() {}

  /** Given the instruction groups of the producer instruction and consumer
   * instruction, plus the producer instruction's destination registers, the
   * bypass latency in cycles is returned.
   * If no bypass is permitted, then -1 is returned. */
  virtual int64_t getBypassLatency(
      const uint16_t producerGroup, const uint16_t consumerGroup,
      const span<Register>& producerDestRegs) const = 0;

 protected:
  /** Map between a producer instruction and the consumer instructions it
   * can forward to.
   * Key = Producer instruction group
   * Value = Pair of Vectors: LHS = Registers which producer updates
   *                          RHS = Consumer Instructions
   * */
  std::unordered_map<uint16_t, std::pair<Register, std::vector<bypassConsumer>>>
      bypassMap_;
};
}  // namespace simeng