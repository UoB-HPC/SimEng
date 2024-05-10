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
  const uint32_t encoding;

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
            const arch::Architecture& isa, BranchPredictor& branchPredictor);

  ~FetchUnit();

  /** Tick the fetch unit. Retrieves and pre-decodes the instruction at the
   * current program counter. */
  void tick();

  /** Function handle to retrieve branch that represents loop boundary. */
  void registerLoopBoundary(uint64_t branchAddress);

  /** Check whether the program has ended. Returns `true` if the current PC is
   * outside of instruction memory. */
  bool hasHalted() const;

  /** Update the program counter to the specified address. */
  void updatePC(uint64_t address);

  /** Request instructions at the current program counter for a future cycle. */
  void requestFromPC();

  /** Retrieve the number of cycles fetch terminated early due to a predicted
   * branch. */
  uint64_t getBranchStalls() const;

  /** Clear the loop buffer. */
  void flushLoopBuffer();

  /** Retrieve the number of branch instructions that have been fetched. */
  uint64_t getBranchFetchedCount() const;

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

  /** A loop buffer to supply a detected loop instruction stream. */
  std::deque<loopBufferEntry> loopBuffer_;

  /** State of the loop buffer. */
  LoopBufferState loopBufferState_ = LoopBufferState::IDLE;

  /** The branch instruction that forms the loop. */
  uint64_t loopBoundaryAddress_ = 0;

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

  /** The buffer used to hold fetched instruction data. */
  uint8_t* fetchBuffer_;

  /** The amount of data currently in the fetch buffer. */
  uint16_t bufferedBytes_ = 0;

  /** The number of branch instructions that were fetched. */
  uint64_t branchesFetched_ = 0;

  /** Let the following PipelineFetchUnitTest derived classes be a friend of
   * this class to allow proper testing of 'tick' function. */
  friend class PipelineFetchUnitTest_invalidMinBytesAtEndOfBuffer_Test;
  friend class PipelineFetchUnitTest_minSizeInstructionAtEndOfBuffer_Test;
  friend class PipelineFetchUnitTest_validMinSizeReadsDontComplete_Test;
  friend class PipelineFetchUnitTest_invalidMinBytesreadsDontComplete_Test;
};

}  // namespace pipeline
}  // namespace simeng
