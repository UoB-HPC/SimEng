#pragma once

#include "simeng/Accelerator.hh"
#include "simeng/arch/aarch64/ExceptionHandler.hh"
#include "simeng/branchpredictors/AlwaysNotTakenPredictor.hh"
#include "simeng/pipeline/DispatchIssueUnit.hh"
#include "simeng/pipeline/ExecuteUnit.hh"
#include "simeng/pipeline/MappedRegisterFileSet.hh"
#include "simeng/pipeline/RenameUnit.hh"
#include "simeng/pipeline/WritebackUnit.hh"

namespace simeng {
namespace models {
namespace accelerator {

class SmeAccelerator : public Accelerator {
 public:
  explicit SmeAccelerator(
      id_t id, gateway_t::send_fn_t send_fn, gateway_t::receive_fn_t receive_fn,
      memory::MemoryInterface& dataMemory,
      pipeline::PortAllocator& portAllocator,
      ryml::ConstNodeRef config = config::SimInfo::getConfig());

  /** An instruction filter which decides whether it should be offloaded
   * to the SME accelerator. */
  static bool shouldAccelerate(const Instruction& insn);

  /** A predicate function for checking whether an accelerated instruction
   * is ready to be sent to the accelerator. */
  static bool isInstructionReady(const Instruction& insn);

  /** A predicate function for checking whether a register is present
   * on the accelerator and should be ignored on the core. */
  static bool isRegisterOffloaded(const Register& reg);

 private:
  /** Concrete implementation of ticking this accelerator. */
  void tickImpl() override;

  /** Marks the instruction as accelerated and adds it to `insns_`. */
  void mapIncoming(std::shared_ptr<Instruction>& insn) override;

  /** Determines whether the provided register is a vector/matrix register. */
  static bool isSmeRegister(const Register& reg);

  /** Flushes the pipeline if required. */
  void flushIfNeeded();

  /** Raise an exception to the core, providing the generating instruction. */
  void raiseException(const std::shared_ptr<Instruction>& instruction);

  /** Handle an exception raised during the cycle. */
  void handleException();

  /** Handle Modifying the register state on an SME state change. */
  void handleSmeStateChange(const arch::aarch64::Instruction& instruction);

  /** Flush the SME accelerator. */
  void flush(uint64_t flushAfter);

  /** Stub branch predictor */
  AlwaysNotTakenPredictor branchPredictor_;

  /** The core's register file set. */
  RegisterFileSet registerFileSet_;

  const std::vector<RegisterFileStructure> physicalRegisterStructures_;

  const std::vector<uint16_t> physicalRegisterQuantities_;

  /** The core's register alias table. */
  pipeline::RegisterAliasTable registerAliasTable_;

  /** The mapped register file set. */
  pipeline::MappedRegisterFileSet mappedRegisterFileSet_;

  /** The buffer between rename and dispatch/issue. */
  pipeline::PipelineBuffer<std::shared_ptr<Instruction>>
      renameToDispatchBuffer_;

  /** The issue ports; single-width buffers between issue and execute. */
  std::vector<pipeline::PipelineBuffer<std::shared_ptr<Instruction>>>
      issuePorts_;

  /** The completion slots; single-width buffers between execute and writeback.
   */
  std::vector<pipeline::PipelineBuffer<std::shared_ptr<Instruction>>>
      completionSlots_;

  /** The rename unit; renames instruction registers. */
  pipeline::RenameUnit renameUnit_;

  /** The dispatch/issue unit; dispatches instructions to the reservation
   * station, reads operands, and issues ready instructions to the execution
   * unit. */
  pipeline::DispatchIssueUnit dispatchIssueUnit_;

  /** The set of execution units; executes uops and sends to writeback, also
   * forwarding results to dispatch/issue. */
  std::vector<pipeline::ExecuteUnit> executionUnits_;

  /** The writeback unit; writes uop results to the register files. */
  pipeline::WritebackUnit writebackUnit_;

  /** The core's reorder buffer. */
  pipeline::ReorderBuffer reorderBuffer_;

  /** The core's load/store queue. */
  pipeline::LoadStoreQueue loadStoreQueue_;

  /** The port allocator unit; allocates a port that an instruction will be
   * issued from based on a defined algorithm. */
  pipeline::PortAllocator& portAllocator_;

  /** Core commit width; maximum number of instruction that can be committed per
   * cycle. */
  const uint64_t commitWidth_ = 0;

  /** A queue of in-flight instructions. */
  std::deque<std::shared_ptr<Instruction>> insns_;

  /** A pointer to the instruction responsible for generating an exception
   * during this cycle, if any. */
  std::optional<std::shared_ptr<Instruction>> exceptionInsn_ = std::nullopt;
};

}  // namespace accelerator
}  // namespace models
}  // namespace simeng
