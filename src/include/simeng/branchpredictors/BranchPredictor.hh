#pragma once

#include <cstdint>
#include <tuple>

#include "simeng/Instruction.hh"
#include "simeng/branchpredictors/BranchPrediction.hh"
#include "simeng/pipeline/PipelineBuffer.hh"

namespace simeng {

/** An abstract branch predictor interface. */
class BranchPredictor {
 public:
  virtual ~BranchPredictor(){};

  /** Generate a branch prediction for the supplied instruction address, a
   * branch type, and a known branch offset.  Returns a branch direction and
   * branch target address. */
  virtual BranchPrediction predict(uint64_t address, BranchType type,
                                   int64_t knownOffset) = 0;

  /** Updates appropriate predictor model objects based on the address, type and
   * outcome of the branch instruction.  Update must be called on
   * branches in program order.  To check this, instructionId is also passed
   * to this function. */
  virtual void update(uint64_t address, bool isTaken, uint64_t targetAddress,
                      BranchType type, uint64_t instructionId) = 0;

  /** Provides flushing behaviour for the implemented branch prediction schemes
   * via the instruction address.  Branches must be flushed in reverse
   * program order (though, if a block of n instructions is being flushed at
   * once, the exact order that the individual instructions within this block
   * are flushed does not matter so long as they are all flushed). */
  virtual void flush(uint64_t address) = 0;

  /**
   * Overloaded function for flushing branch instructions from a
   * PipelineBuffer. Accepts a reference to a PipelineBuffer of microOps.
   * Iterates over the entries of the PipelineBuffer and, if they are a
   * branch instruction, flushes them.
   */
  void flushBranchesInBufferFromSelf(
      pipeline::PipelineBuffer<std::shared_ptr<Instruction>>& buffer) {
    for (size_t slot = 0; slot < buffer.getWidth(); slot++) {
      auto& uop = buffer.getTailSlots()[slot];
      if (uop != nullptr && uop->isBranch()) {
        flush(uop->getInstructionAddress());
      }

      uop = buffer.getHeadSlots()[slot];
      if (uop != nullptr && uop->isBranch()) {
        flush(uop->getInstructionAddress());
      }
    }
  }

  /**
   * Overloaded function for flushing branch instructions from a
   * PipelineBuffer. Accepts a reference to a PipelineBuffer macroOps.
   * Iterates over the entries of the PipelineBuffer and, if they are a
   * branch instruction, flushes them.
   */
  void flushBranchesInBufferFromSelf(
      pipeline::PipelineBuffer<std::vector<std::shared_ptr<Instruction>>>&
          buffer) {
    for (size_t slot = 0; slot < buffer.getWidth(); slot++) {
      auto& macroOp = buffer.getTailSlots()[slot];
      for (size_t uop = 0; uop < macroOp.size(); uop++) {
        if (macroOp[uop]->isBranch()) {
          flush(macroOp[uop]->getInstructionAddress());
        }
      }
      macroOp = buffer.getHeadSlots()[slot];
      for (size_t uop = 0; uop < macroOp.size(); uop++) {
        if (macroOp[uop]->isBranch()) {
          flush(macroOp[uop]->getInstructionAddress());
        }
      }
    }
  }

  /** lastUpdatedInstructionId_ is used only in debug mode. Clang throws a
   * warning (which becomes an error with our cmake flags) for unused
   * variables. If the [[maybe_unused]] attribute is added to avoid this,
   * then gcc throws a warning (which becomes an error) because it ignores
   * this attribute. Therefore, to avoid the above catch 22, this variable is
   * hidden behind an ifdef such that it is declared only in debug mode; when
   * it is used. */
#ifndef NDEBUG
  /** The Id of the last instruction that update was called on -- used to
   * ensure that update is called in program order. */
  uint64_t lastUpdatedInstructionId_ = 0;
#endif
};

}  // namespace simeng