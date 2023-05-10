#pragma once

#include <deque>
#include <initializer_list>
#include <queue>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

#include "simeng/Config.hh"
#include "simeng/Instruction.hh"
#include "simeng/pipeline/InOrderStager.hh"
#include "simeng/pipeline/LoadStoreQueue.hh"
#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/pipeline/PortAllocator.hh"

namespace simeng {
namespace pipeline {

/** An issue unit for an inorder pipelined processor. Reads instruction operands
 * and performs scoreboarding. Issues instructions to the execution units once
 * ready in program-order. */
class BlockingIssueUnit {
 public:
  /** Construct an issue unit with references to input/output buffers,
   * the register file, the port allocator, and a description of the number
   * of physical registers the scoreboard needs to reflect. */
  BlockingIssueUnit(
      PipelineBuffer<std::shared_ptr<Instruction>>& input,
      std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts,
      PortAllocator& portAllocator,
      std::function<void(const std::shared_ptr<Instruction>&)> recordIssue,
      LoadStoreQueue& lsq,
      std::function<void(const std::shared_ptr<Instruction>&)> raiseException,
      const RegisterFileSet& registerFileSet,
      const std::vector<uint16_t>& physicalRegisterStructure);

  /** Ticks the issue unit. Reads available input operands for
   * instructions and sets scoreboard flags for destination registers. If the
   * resources required by an instruction aren't available, the unit and its
   * input buffer are stalled until its ready to be issued. */
  void tick();

  /** Forwards operands to the instruction at the front of the issue queue and
   * issues it if ready to execute. */
  void forwardOperands(const span<Register>& destinations,
                       const span<RegisterValue>& values);

  /** Set the scoreboard entry for the provided register as ready. */
  void setRegisterReady(Register reg);

  /** Flush the scoreboard entries which have been set by instructions older
   * than the sequence id provided. Also clear any register source dependency
   * and clear the issue queue. */
  void flush(uint64_t afterSeqId);

  /** Flush the scoreboard entries, clear any register source dependency
   * and clear the issue queue. */
  void flush();

  /** Retrieve the number of cycles no instructions were issued due to an empty
   * issue queue. */
  uint64_t getFrontendStalls() const;

  /** Retrieve the number of cycles no instructions were issued due to
   * dependencies or a lack of available ports. */
  uint64_t getBackendStalls() const;

  /** Retrieve the number of times an instruction was unable to issue due to a
   * busy port. */
  uint64_t getPortBusyStalls() const;

 private:
  /** A buffer of instructions to issue and read operands for. */
  PipelineBuffer<std::shared_ptr<Instruction>>& input_;

  /** Ports to the execution units, for writing ready instructions to. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts_;

  /** A queue of instructions, in program-order, which are ready to be issued.
   */
  std::deque<std::shared_ptr<Instruction>> issueQueue_;

  /** A reference to the execution port allocator. */
  PortAllocator& portAllocator_;

  /** The register availability scoreboard. An unsigned integer is used to set
   * the instruction which made a register unavailable. */
  std::vector<std::vector<std::pair<bool, uint64_t>>> scoreboard_;

  /** A function to record the issue of an instruction to enable the tracking of
   * in program-order instruction execution and writeback. */
  std::function<void(const std::shared_ptr<Instruction>&)> recordIssue_;

  /** A reference to the load/store queue. */
  LoadStoreQueue& lsq_;

  /** A function handle called upon exception generation. */
  std::function<void(const std::shared_ptr<Instruction>&)> raiseException_;

  /** A reference to the physical register file set. */
  const RegisterFileSet& registerFileSet_;

  /** Whether the supply of a source operand is dependent on a currently
   * executing instruction. */
  bool dependent_ = false;

  /** A pair representing a register dependency. The first entry in the pair is
   * the register depended on, and the second is the operand index, within the
   * dependent instruction, the dependency is associated with. */
  std::pair<Register, uint16_t> dependency_;

  /** The number of cycles no instructions were issued due to an empty issue
   * queue. */
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
