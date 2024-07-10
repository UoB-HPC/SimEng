#pragma once

#include "simeng/OperandBypassMap.hh"

namespace simeng {
namespace arch {
namespace riscv {

/** A simple class to hold the permitted operand bypass model and easily find
   the bypass latency between two instructions. */
class NoneToNoneBypassMap : public OperandBypassMap {
 public:
  NoneToNoneBypassMap() {}

  /** Given the instruction groups of the producer instruction and consumer
   * instruction, plus the producer instruction's destination registers, the
   * bypass latency in cycles is returned.
   * If no bypass is permitted, then -1 is returned. */
  int64_t getBypassLatency(
      const uint16_t producerGroup, const uint16_t consumerGroup,
      const span<Register>& producerDestRegs) const override {
    // None to None map means no forwarding is allowed in any case
    return -1;
  }

 private:
};

}  // namespace riscv
}  // namespace arch
}  // namespace simeng