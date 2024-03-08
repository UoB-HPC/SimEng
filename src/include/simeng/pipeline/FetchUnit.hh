#pragma once

#include <queue>

#include "simeng/arch/Architecture.hh"
#include "simeng/memory/MemoryInterface.hh"
#include "simeng/pipeline/PipelineBuffer.hh"

namespace simeng {
namespace pipeline {

/** The various states of the loop buffer. */
enum class LoopBufferState {
  IDLE = 0,  // No operations
  WAITING,   // Waiting to find boundary instruction in fetch stream
  FILLING,   // Filling loop buffer with loop body
  SUPPLYING  // Feeding loop buffer content to output buffer
};

// Struct to hold information about a fetched instruction
struct loopBufferEntry {
  // Encoding of the instruction
  const uint64_t encoding;

  // Size of the instruction
  const uint16_t instructionSize;

  // PC of the instruction
  const uint64_t address;

  // Branch prediction made for instruction
  const BranchPrediction prediction;
};

/** A fetch and pre-decode unit for a pipelined processor. Responsible for
 * reading instruction memory and maintaining the program counter. */
class FetchUnit {
 public:
  /** Construct a fetch unit with a reference to an output buffer, the ISA, and
   * the current branch predictor, and information on the instruction memory. */
  FetchUnit(PipelineBuffer<MacroOp>& output,
            memory::MemoryInterface& instructionMemory,
            uint64_t programByteLength, uint64_t entryPoint, uint16_t blockSize,
            const arch::Architecture& isa, BranchPredictor& branchPredictor,
            uint16_t mopQueueSize, uint8_t mopCacheTagBits);

  ~FetchUnit();

  /** Tick the fetch unit. Retrieves and pre-decodes the instruction at the
   * current program counter. */
  void tick();

  /** Check whether the program has ended. Returns `true` if the current PC is
   * outside of instruction memory. */
  bool hasHalted() const;

  /** Update the program counter to the specified address. */
  void updatePC(uint64_t address);

  /** Retrieve the number of cycles fetch terminated early due to a predicted
   * branch. */
  uint64_t getBranchStalls() const;

 private:
  /** An output buffer connecting this unit to the decode unit. */
  PipelineBuffer<MacroOp>& output_;

  /** The current program counter. */
  uint64_t pc_ = 0;

  /** An interface to the instruction memory. */
  memory::MemoryInterface& instructionMemory_;

  /** The length of the available instruction memory. */
  uint64_t programByteLength_;

  /** Reference to the currently used ISA. */
  const arch::Architecture& isa_;

  /** Reference to the current branch predictor. */
  BranchPredictor& branchPredictor_;

  uint16_t mopQueueSize_ = 0;

  std::deque<MacroOp> mopQueue_;

  uint8_t mopCacheTagBits_ = 0;

  std::vector<std::pair<uint64_t, uint64_t>> mopCache_;

  std::vector<uint64_t> requestedBlocks_;

  /** The current program halt state. Set to `true` when the PC leaves the
   * instruction memory region, and set back to `false` if the PC is returned to
   * the instruction region. */
  bool hasHalted_ = false;

  /** The number of cycles fetch terminated early due to a predicted branch. */
  uint64_t branchStalls_ = 0;

  /** The size of a fetch block, in bytes. */
  uint16_t blockSize_;

  /** A mask of the bits of the program counter to use for obtaining the block
   * address to fetch. */
  uint64_t blockMask_;

  /** Let the following PipelineFetchUnitTest derived classes be a friend of
   * this class to allow proper testing of 'tick' function. */
  friend class PipelineFetchUnitTest_invalidMinBytesAtEndOfBuffer_Test;
  friend class PipelineFetchUnitTest_minSizeInstructionAtEndOfBuffer_Test;
  friend class PipelineFetchUnitTest_validMinSizeReadsDontComplete_Test;
  friend class PipelineFetchUnitTest_invalidMinBytesreadsDontComplete_Test;
};

}  // namespace pipeline
}  // namespace simeng
