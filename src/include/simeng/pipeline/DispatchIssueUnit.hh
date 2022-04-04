#pragma once

#include <deque>
#include <initializer_list>
#include <queue>
#include <unordered_map>
#include <unordered_set>

#include "simeng/Instruction.hh"
#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/pipeline/PortAllocator.hh"

namespace simeng {
namespace pipeline {

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
}  // namespace ConsumerGroups

/** A reservation station issue port */
struct ReservationStationPort {
  /** Issue port this port maps to */
  uint8_t issuePort;
  /** Queue of instructions that are ready to be
   * issued */
  std::deque<std::shared_ptr<Instruction>> ready;
};

/** A reservation station */
struct ReservationStation {
  /** Size of reservation station */
  uint16_t capacity;
  /** Current number of non-stalled instructions
   * in reservation station */
  uint16_t currentSize;
  /** Issue ports belonging to reservation station */
  std::vector<ReservationStationPort> ports;
};

/** An entry in the reservation station. */
struct dependencyEntry {
  /** The instruction to execute. */
  std::shared_ptr<Instruction> uop;
  /** The port to issue to. */
  uint8_t port;
  /** The operand waiting on a value. */
  uint8_t operandIndex;
};

/** A dispatch/issue unit for an out-of-order pipelined processor. Reads
 * instruction operand and performs scoreboarding. Issues instructions to the
 * execution unit once ready. */
class DispatchIssueUnit {
 public:
  /** Construct a dispatch/issue unit with references to input/output buffers,
   * the register file, the port allocator, and a description of the number of
   * physical registers the scoreboard needs to reflect. */
  DispatchIssueUnit(
      PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
      std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts,
      const RegisterFileSet& registerFileSet, PortAllocator& portAllocator,
      const std::vector<uint16_t>& physicalRegisterStructure,
      std::vector<std::pair<uint8_t, uint64_t>> rsArrangment,
      uint8_t dispatchRate = UINT8_MAX);

  /** Ticks the dispatch/issue unit. Reads available input operands for
   * instructions and sets scoreboard flags for destination registers. */
  void tick();

  /** Identify the oldest ready instruction in the reservation station and issue
   * it. */
  void issue();

  /** Forwards operands and performs register reads for the currently queued
   * instruction. */
  void forwardOperands(const span<Register>& destinations,
                       const span<RegisterValue>& values,
                       const uint16_t uopGroup);

  /** Set the scoreboard entry for the provided register as ready. */
  void setRegisterReady(Register reg);

  /** Clear the RS of all flushed instructions. */
  void purgeFlushed();

  /** Retrieve the number of cycles this unit stalled due to insufficient RS
   * space. */
  uint64_t getRSStalls() const;

  /** Retrieve the number of cycles no instructions were issued due to an empty
   * RS. */
  uint64_t getFrontendStalls() const;

  /** Retrieve the number of cycles no instructions were issued due to
   * dependencies or a lack of available ports. */
  uint64_t getBackendStalls() const;

  /** Retrieve the number of times an instruction was unable to issue due to a
   * busy port. */
  uint64_t getPortBusyStalls() const;

  /** Retrieve the current sizes and capacities of the reservation stations*/
  void getRSSizes(std::vector<uint64_t>&) const;

 private:
  /** Function which given an Instruction will return the ProducerGroup it falls
   * into. */
  uint16_t getProducerGroup(std::shared_ptr<Instruction> uop);

  /** Function which given an Instruction will return the ConsumerGroup it falls
   * into. */
  uint16_t getConsumerGroup(std::shared_ptr<Instruction> uop);

  /** A buffer of instructions to dispatch and read operands for. */
  PipelineBuffer<std::shared_ptr<Instruction>>& input_;

  /** Ports to the execution units, for writing ready instructions to. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts_;

  /** A reference to the physical register file set. */
  const RegisterFileSet& registerFileSet_;

  /** The register availability scoreboard. */
  std::vector<std::vector<bool>> scoreboard_;

  /** Reservation stations */
  std::vector<ReservationStation> reservationStations_;

  /** Stores the number of instructions dispatched each cycle, for each
  reservation station. */
  std::vector<uint8_t> dispatches = {};

  /** A mapping from port to RS port */
  std::vector<std::pair<uint8_t, uint8_t>> portMapping_;

  /** A dependency matrix, containing all the instructions waiting on an
   * operand. For a register `{type,tag}`, the vector of dependents may be found
   * at `dependencyMatrix[type][tag]`. */
  std::vector<std::vector<std::vector<dependencyEntry>>> dependencyMatrix_;

  /** A map to collect flushed instructions for each reservation station. */
  std::unordered_map<uint8_t, std::unordered_set<std::shared_ptr<Instruction>>>
      flushed_;

  /** A reference to the execution port allocator. */
  PortAllocator& portAllocator_;

  /** The number of instructions that can be dispatched to a reservation station
   * per cycle. */
  uint64_t dispatchRate_;

  /** The number of cycles stalled due to a full reservation station. */
  uint64_t rsStalls_ = 0;

  /** The number of cycles no instructions were issued due to an empty RS. */
  uint64_t frontendStalls_ = 0;

  /** The number of cycles no instructions were issued due to dependencies or a
   * lack of available ports. */
  uint64_t backendStalls_ = 0;

  /** The number of times an instruction was unable to issue due to a busy port.
   */
  uint64_t portBusyStalls_ = 0;

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
};
}  // namespace pipeline
}  // namespace simeng
