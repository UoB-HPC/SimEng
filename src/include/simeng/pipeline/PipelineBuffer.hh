#pragma once

#include <algorithm>
#include <memory>
#include <vector>

#include "simeng/BranchPredictor.hh"

namespace simeng {
namespace pipeline {

// TODO: Extend to allow specifying the number of cycles it will take for
// information to move from tail to head (currently fixed at 1 by
// implementation)

/** A tickable pipelined buffer. Values are shifted from the tail slot to the
 * head slot each time `tick()` is called. */
template <class T>
class PipelineBuffer {
 public:
  /** Construct a pipeline buffer of width `width`, and fill all slots with
   * `initialValue`. */
  PipelineBuffer(uint16_t width, const T& initialValue)
      : width(width), buffer(width * length, initialValue) {}

  /** Tick the buffer and move head/tail pointers, or do nothing if it's
   * stalled. */
  void tick() {
    if (isStalled_) return;

    headIsStart = !headIsStart;
  }

  /** Return the slots waiting to be processed by the next pipeline unit */
  const T* getPendingSlots() const {
    // If stalled head and tail slots won't have been swapped
    if (isStalled_) {
      return getTailSlots();
    } else {
      return getHeadSlots();
    }
  }

  /** Get a tail slots pointer. */
  T* getTailSlots() {
    T* ptr = buffer.data();
    return &ptr[headIsStart * width];
  }
  /** Get a const tail slots pointer. */
  const T* getTailSlots() const {
    const T* ptr = buffer.data();
    return &ptr[headIsStart * width];
  }

  /** Get a head slots pointer. */
  T* getHeadSlots() {
    T* ptr = buffer.data();
    return &ptr[!headIsStart * width];
  }
  /** Get a const head slots pointer. */
  const T* getHeadSlots() const {
    const T* ptr = buffer.data();
    return &ptr[!headIsStart * width];
  }

  /** Check if the buffer is stalled. */
  bool isStalled() const { return isStalled_; }

  /** Set the buffer's stall flag to `stalled`. */
  void stall(bool stalled) { isStalled_ = stalled; }

  /** Fill the buffer with a specified value. */
  void fill(const T& value) { std::fill(buffer.begin(), buffer.end(), value); }

  /** Get the width of the buffer slots. */
  uint16_t getWidth() const { return width; }

  void flushBranchMicroOps(BranchPredictor& branchPredictor) {
    for (size_t slot = 0; slot < width; slot++) {
      auto& uop = getTailSlots()[slot];
      if (uop != nullptr && uop->isBranch()) {
        branchPredictor.flush(uop->getInstructionAddress());
      }
      uop = getHeadSlots()[slot];
      if (uop != nullptr && uop->isBranch()) {
        branchPredictor.flush(uop->getInstructionAddress());
      }
    }
  }

  void flushBranchMacroOps(BranchPredictor& branchPredictor) {
    for (size_t slot = 0; slot < width; slot++) {
      auto& macroOp = getTailSlots()[slot];
      if (!macroOp.empty() && macroOp[0]->isBranch()) {
        branchPredictor.flush(macroOp[0]->getInstructionAddress());
      }
      macroOp = getHeadSlots()[slot];
      if (!macroOp.empty() && macroOp[0]->isBranch()) {
        branchPredictor.flush(macroOp[0]->getInstructionAddress());
      }
    }
  }

 private:
  /** The width of each row of slots. */
  uint16_t width;

  /** The buffer. */
  std::vector<T> buffer;

  /** The offset of the head pointer; either 0 or 1. */
  bool headIsStart = 0;

  /** Whether the buffer is stalled or not. */
  bool isStalled_ = false;

  /** The number of stages in the pipeline. */
  static const unsigned int length = 2;
};

}  // namespace pipeline
}  // namespace simeng
