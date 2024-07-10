#pragma once

#include <map>

#include "include/simeng/Register.hh"
#include "include/simeng/span.hh"

namespace simeng {

/** A struct to define a producer instruction. */
struct bypassProducer {
  uint16_t group;
  std::vector<Register> destRegs;
}

/** A struct to define a consumer instruction. */
struct bypassConsumer {
  uint16_t group;
  uint64_t latency;
}

/** A simple class to hold the permitted operand bypass model and easily find
   the bypass latency between two instructions. */
class OperandBypassMap {
 public:
  OperandBypassMap();

  /** Given the instruction groups of the producer instruction and consumer
   * instruction, plus the producer instruction's destination registers, the
   * bypass latency in cycles is returned.
   * If no bypass is permitted, then -1 is returned. */
  virtual int64_t getBypassLatency(
      const uint16_t producerGroup, const uint16_t consumerGroup,
      const span<Register>& producerDestRegs) const = 0;

 private:
  /** Map between a producer instruction and the consumer instructions it can
   * forward to. */
  std::unordered_map<bypassProducer, std::vector<bypassConsumer>> bypassMap_;
}
}  // namespace simeng