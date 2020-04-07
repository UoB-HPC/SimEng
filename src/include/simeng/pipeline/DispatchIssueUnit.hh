#pragma once

#include <deque>
#include <queue>

#include "simeng/Instruction.hh"
#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/pipeline/PortAllocator.hh"

namespace simeng {
namespace pipeline {

/** An entry in the reservation station. */
struct ReservationStationEntry {
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
      std::vector<std::pair<uint8_t, uint64_t>> rsArrangment);

  /** Ticks the dispatch/issue unit. Sends the stalled instructions and 
   * incoming from rename instructions to resourceAllocation function. */
  void tick();

  /** Reads available input operands for a given instruction and sets 
   * scoreboard flags for destination registers. */
  void resourceAllocation(std::shared_ptr<Instruction> uop, uint8_t port);
   
  /** Identify the oldest ready instruction in the reservation station and issue
   * it. */
  void issue();

  /** Forwards operands and performs register reads for the currently queued
   * instruction. */
  void forwardOperands(const span<Register>& destinations,
                       const span<RegisterValue>& values);

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

 private:
  /** A buffer of instructions to dispatch and read operands for. */
  PipelineBuffer<std::shared_ptr<Instruction>>& input_;

  /** Ports to the execution units, for writing ready instructions to. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts_;

  /** A reference to the physical register file set. */
  const RegisterFileSet& registerFileSet_;

  /** The register availability scoreboard. */
  std::vector<std::vector<bool>> scoreboard_;

  /** The maximum number of items permitted in each RS */
  std::vector<size_t> maxReservationStationSize_;

  /** A mapping from port to RS port */
  std::vector<std::pair<uint8_t, uint8_t>> portMapping_;

  /** A dependency matrix, containing all the instructions waiting on an
   * operand. For a register `{type,tag}`, the vector of dependents may be found
   * at `dependencyMatrix[type][tag]`. */
  std::vector<std::vector<std::vector<ReservationStationEntry>>>
      dependencyMatrix_;

  /** A reference to the execution port allocator. */
  PortAllocator& portAllocator_;

  /** The queues of ready instructions for each port. */
  std::vector<std::vector<std::pair<uint8_t, std::deque<std::shared_ptr<Instruction>>>>> readyQueues_;
  
  /** The queues of stalled instructions for each port. */
  std::vector<std::vector<std::pair<uint8_t, std::deque<std::shared_ptr<Instruction>>>>> stallQueues_;

  /** The number of items currently in each RS. */
  std::vector<size_t> rsSize_;

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
};

}  // namespace pipeline
}  // namespace simeng
