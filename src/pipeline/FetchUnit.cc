#include "FetchUnit.hh"

#include <iostream>

namespace simeng {
namespace pipeline {

FetchUnit::FetchUnit(PipelineBuffer<MacroOp>& output,
                     MemoryInterface& instructionMemory,
                     uint64_t programByteLength, uint64_t entryPoint,
                     const Architecture& isa, BranchPredictor& branchPredictor)
    : output_(output),
      pc_(entryPoint),
      instructionMemory_(instructionMemory),
      programByteLength_(programByteLength),
      isa_(isa),
      branchPredictor_(branchPredictor) {
  requestFromPC();
};

void FetchUnit::tick() {
  if (output_.isStalled()) {
    return;
  }

  if (hasHalted_) {
    return;
  }

  // Find fetched memory that matches the current PC
  const auto& fetched = instructionMemory_.getCompletedReads();
  size_t fetchIndex;
  for (fetchIndex = 0; fetchIndex < fetched.size(); fetchIndex++) {
    if (fetched[fetchIndex].first.address == pc_) {
      break;
    }
  }
  if (fetchIndex == fetched.size()) {
    // Need to wait for fetched instructions
    return;
  }

  // Get a pointer to the fetched data
  const char* buffer = fetched[fetchIndex].second.getAsVector<char>();
  const uint8_t bufferSize = fetched[fetchIndex].first.size;
  uint8_t bufferOffset = 0;

  auto outputSlots = output_.getTailSlots();
  for (size_t slot = 0; slot < output_.getWidth(); slot++) {
    auto& macroOp = outputSlots[slot];

    uint8_t availableBytes = bufferSize - bufferOffset;

    auto prediction = branchPredictor_.predict(pc_);
    auto bytesRead = isa_.predecode(buffer + bufferOffset, availableBytes, pc_,
                                    prediction, macroOp);

    // TODO: Cache and wait if `bytesRead` is 0

    assert(bytesRead <= availableBytes &&
           "Predecode consumed more bytes than were available");
    // Increment the offset
    bufferOffset += bytesRead;

    if (!prediction.taken) {
      // Predicted as not taken; increment PC to next instruction
      pc_ += bytesRead;
    } else {
      // Predicted as taken; set PC to predicted target address
      pc_ = prediction.target;
    }

    if (pc_ >= programByteLength_) {
      hasHalted_ = true;
      break;
    }

    if (prediction.taken) {
      if (slot + 1 < output_.getWidth()) {
        branchStalls_++;
      }
      // Can't continue fetch immediately after a branch
      break;
    }

    // Too few bytes remaining in buffer to continue
    if (bufferOffset == bufferSize) {
      break;
    }
  }

  instructionMemory_.clearCompletedReads();
};

bool FetchUnit::hasHalted() const { return hasHalted_; }

void FetchUnit::updatePC(uint64_t address) {
  pc_ = address;
  hasHalted_ = (pc_ >= programByteLength_);
}

void FetchUnit::requestFromPC() { instructionMemory_.requestRead({pc_, 4}); }

uint64_t FetchUnit::getBranchStalls() const { return branchStalls_; }

}  // namespace pipeline
}  // namespace simeng
