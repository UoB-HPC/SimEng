#pragma once

#include <deque>

#include "../Instruction.hh"
#include "../PipelineBuffer.hh"

namespace simeng {
namespace outoforder {

/** A dispatch/issue unit for an out-of-order pipeline. Reads instruction
 * operand and performs scoreboarding. Issues instructions to the execution unit
 * once ready. */
class DispatchIssueUnit {
 public:
  /** Construct a dispatch/issue unit with references to input/output buffers,
   * the register file, and a description of the number of physical registers
   * the scoreboard needs to reflect. */
  DispatchIssueUnit(
      PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
      std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts,
      const RegisterFile& registerFile,
      const std::vector<uint16_t>& physicalRegisterStructure,
      unsigned int maxReservationStationSize);

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

  /** Retrieve the number of cycles no instructions were issued due to
   * dependencies or a lack of available ports. */
  uint64_t getOutOfOrderIssueCount() const;

 private:
  /** A buffer of instructions to dispatch and read operands for. */
  PipelineBuffer<std::shared_ptr<Instruction>>& fromRenameBuffer;

  /** Ports to the execution units, for writing ready instructions to. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts;

  /** A reference to the physical register file. */
  const RegisterFile& registerFile;

  /** The register availability scoreboard. */
  std::vector<std::vector<bool>> scoreboard;

  /** The maximum reservation station size. */
  unsigned int maxReservationStationSize;

  /** The reservation station. Holds instructions until operands become
   * available. */
  std::deque<std::shared_ptr<Instruction>> reservationStation;

  /** A dependency matrix, containing all the instructions waiting on an
   * operand. For a register `{type,tag}`, the vector of dependents may be found
   * at `dependencyMatrix[type][tag]`. */
  std::vector<std::vector<std::vector<std::shared_ptr<Instruction>>>>
      dependencyMatrix;

  /** The number of instructions ready to execute. */
  unsigned int readyCount = 0;

  /** The number of cycles stalled due to a full reservation station. */
  uint64_t rsStalls = 0;

  /** The number of cycles no instructions were issued due to an empty RS. */
  uint64_t frontendStalls = 0;

  /** The number of cycles no instructions were issued due to dependencies or a
   * lack of available ports. */
  uint64_t backendStalls = 0;

  /** The number of instructions issued out-of-order. */
  uint64_t outOfOrderIssues = 0;
};

}  // namespace outoforder
}  // namespace simeng
