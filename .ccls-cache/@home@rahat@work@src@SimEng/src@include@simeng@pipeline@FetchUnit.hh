#pragma once

#include <queue>

#include "simeng/MemoryInterface.hh"
#include "simeng/arch/Architecture.hh"
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
  FetchUnit(PipelineBuffer<MacroOp>& output, MemoryInterface& instructionMemory,
<<<<<<< HEAD
            uint8_t blockSize, const arch::Architecture& isa,
            BranchPredictor& branchPredictor);
=======
            uint64_t programByteLength, uint64_t entryPoint, uint8_t blockSize,
            const arch::Architecture& isa, BranchPredictor& branchPredictor);
>>>>>>> c36c82eb (added PageArameAllocator decl)

  ~FetchUnit();

  /** Tick the fetch unit. Retrieves and pre-decodes the instruction at the
   * current program counter. */
  void tick();

  /** Function handle to retrieve branch that represents loop boundary. */
  void registerLoopBoundary(uint64_t branchAddress);

  /** Check whether the program has ended. Returns `true` if the current PC is
   * outside of instruction memory. */
  bool hasHalted() const;

<<<<<<< HEAD
  /** Update the program counter to the specified address.
   * NOTE: Must set program length before calling when scheduling.
   */
  void updatePC(uint64_t address);

  /** Update programByteLength_ to the specified value.
   * NOTE: Must be set before updating PC when scheduling.
   */
  void setProgramLength(uint64_t size);

=======
  /** Update the program counter to the specified address. */
  void updatePC(uint64_t address);

>>>>>>> c36c82eb (added PageArameAllocator decl)
  /** Request instructions at the current program counter for a future cycle. */
  void requestFromPC();

  /** Retrieve the number of cycles fetch terminated early due to a predicted
   * branch. */
  uint64_t getBranchStalls() const;

  /** Clear the loop buffer. */
  void flushLoopBuffer();

<<<<<<< HEAD
  /** Temporarily pause the FetchUnit. */
  void pause() {
    paused_ = true;
    instructionMemory_.clearCompletedReads();
    flushLoopBuffer();
  };

  /** Unpause the fetch unit. */
  void unpause() {
    paused_ = false;
    requestFromPC();
  };

  /** Get the current PC value. */
  uint64_t getPC() const { return pc_; };

=======
>>>>>>> c36c82eb (added PageArameAllocator decl)
 private:
  /** An output buffer connecting this unit to the decode unit. */
  PipelineBuffer<MacroOp>& output_;

  /** The current program counter. */
  uint64_t pc_ = 0;

  /** An interface to the instruction memory. */
  MemoryInterface& instructionMemory_;

  /** The length of the available instruction memory. */
<<<<<<< HEAD
  uint64_t programByteLength_ = 0;
=======
  uint64_t programByteLength_;
>>>>>>> c36c82eb (added PageArameAllocator decl)

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
  uint8_t blockSize_;

  /** A mask of the bits of the program counter to use for obtaining the block
   * address to fetch. */
  uint64_t blockMask_;

  /** The buffer used to hold fetched instruction data. */
  uint8_t* fetchBuffer_;

  /** The amount of data currently in the fetch buffer. */
  uint8_t bufferedBytes_ = 0;
<<<<<<< HEAD

  /** The Fetch Unit's paused state - when an interupt has been signalled, the
   * Fetch Unit must not fetch / increment the PC until a new process has been
   * scheduled. This ensures the correct architectural state can be captured
   * during a context switch. */
  bool paused_ = false;
=======
>>>>>>> c36c82eb (added PageArameAllocator decl)
};

}  // namespace pipeline
}  // namespace simeng
