#pragma once

#include <deque>
#include <queue>

#include "simeng/Instruction.hh"
#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/pipeline/PortAllocator.hh"

namespace simeng {
namespace pipeline {

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
  uint64_t capacity;
  /** Current number of non-stalled instructions
   * in reservation station */
  uint64_t currentSize;
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

  /** Retrieve the current sizes and capacities of the reservation stations*/
  void getRSSizes(std::vector<uint64_t>&) const;

 private:
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

  /** A mapping from port to RS port */
  std::vector<std::pair<uint8_t, uint8_t>> portMapping_;

  /** A dependency matrix, containing all the instructions waiting on an
   * operand. For a register `{type,tag}`, the vector of dependents may be found
   * at `dependencyMatrix[type][tag]`. */
  std::vector<std::vector<std::vector<dependencyEntry>>> dependencyMatrix_;

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
};

}  // namespace pipeline
}  // namespace simeng
