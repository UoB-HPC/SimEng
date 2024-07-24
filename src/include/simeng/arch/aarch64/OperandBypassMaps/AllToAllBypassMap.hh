#pragma once

#include "simeng/OperandBypassMap.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** A simple class to hold the permitted operand bypass model and easily find
   the bypass latency between two instructions. */
class AllToAllBypassMap : public OperandBypassMap {
 public:
  AllToAllBypassMap() {}

  /** Given the instruction groups of the producer instruction and consumer
   * instruction, plus the forwarded operand's register type, the
   * bypass latency in cycles is returned.
   * If no bypass is permitted, then -1 is returned. */
  int64_t getBypassLatency(const uint16_t producerGroup,
                           const uint16_t consumerGroup,
                           const uint8_t regType) override {
    // All to All map means any producer can forward to any consumer with 0
    // latency
    return 0;
  }

 private:
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng