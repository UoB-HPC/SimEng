#pragma once

#include <map>
#include <optional>
#include <set>

#include "simeng/Register.hh"
#include "simeng/span.hh"

namespace simeng {

/** A struct to define a consumer instruction. */
struct bypassConsumer {
  std::vector<uint16_t> groups = {};
  uint64_t latency = 0;
};

/** A simple class to hold the permitted operand bypass model and easily find
   the bypass latency between two instructions. */
class OperandBypassMap {
 public:
  OperandBypassMap() {}
  virtual ~OperandBypassMap() {}

  /** Given the instruction groups of the producer instruction and consumer
   * instruction, plus the forwarded operand's register type, the
   * bypass latency in cycles is returned.
   * If no bypass is permitted, then -1 is returned. */
  virtual int64_t getBypassLatency(const uint16_t producerGroup,
                                   const uint16_t consumerGroup,
                                   const uint8_t regType) const = 0;

 protected:
  /** Map between a producer instruction and the set of consumer instructions it
   * can forward to.
   *
   * There can be multiple sets of consumer instructions per producer, either
   * due to different latencies, or due to the bypass validity being dependant
   * on the operand register type.
   * */
  std::unordered_map<uint16_t,
                     std::vector<std::pair<std::optional<uint8_t>,
                                           std::vector<bypassConsumer>>>>
      bypassMap_;
};
}  // namespace simeng