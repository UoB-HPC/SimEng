#include "simeng/pipeline/FetchUnit.hh"

namespace simeng {
namespace pipeline {

FetchUnit::FetchUnit(PipelineBuffer<MacroOp>& output,
                     MemoryInterface& instructionMemory,
                     uint64_t programByteLength, uint64_t entryPoint,
                     uint16_t blockSize, const arch::Architecture& isa,
                     BranchPredictor& branchPredictor)
    : output_(output),
      pc_(entryPoint),
      instructionMemory_(instructionMemory),
      programByteLength_(programByteLength),
      isa_(isa),
      branchPredictor_(branchPredictor),
      blockSize_(blockSize),
      blockMask_(~(blockSize_ - 1)) {
  assert(blockSize_ >= isa_.getMaxInstructionSize() &&
         "fetch block size must be larger than the largest instruction");
  fetchBuffer_ = new uint8_t[2 * blockSize_];
  requestFromPC();
}

FetchUnit::~FetchUnit() { delete[] fetchBuffer_; }

void FetchUnit::tick() {
  std::cout << "tick pc=" << pc_ << " bufferedBytes=" << (int)bufferedBytes_
            << std::endl;

  if (output_.isStalled()) {
    return;
  }

  if (hasHalted_) {
    return;
  }

  // If loop buffer has been filled, fill buffer to decode
  if (loopBufferState_ == LoopBufferState::SUPPLYING) {
    auto outputSlots = output_.getTailSlots();
    for (size_t slot = 0; slot < output_.getWidth(); slot++) {
      auto& macroOp = outputSlots[slot];
      auto bytesRead = isa_.predecode(&(loopBuffer_.front().encoding),
                                      loopBuffer_.front().instructionSize,
                                      loopBuffer_.front().address, macroOp);

      assert(bytesRead != 0 && "predecode failure for loop buffer entry");

      // Set prediction to recorded value during loop buffer filling
      if (macroOp[0]->isBranch()) {
        macroOp[0]->setBranchPrediction(loopBuffer_.front().prediction);
      }

      // Cycle queue by moving front entry to back
      loopBuffer_.push_back(loopBuffer_.front());
      loopBuffer_.pop_front();
    }
    return;
  }

  // Pointer to the instruction data to decode from
  const uint8_t* buffer;
  uint8_t bufferOffset;

  // Check if more instruction data is required
  if (bufferedBytes_ < isa_.getMaxInstructionSize()) {
    std::cout << "more data required" << std::endl;

    // Calculate the address of the next fetch block
    uint64_t blockAddress;
    if (bufferedBytes_ > 0) {
      // There is already some data in the buffer, so check for the next block
      bufferOffset = 0;
      blockAddress = pc_ + bufferedBytes_;
      assert((blockAddress & ~blockMask_) == 0 && "misaligned fetch buffer");
    } else {
      // Fetch buffer is empty, so start from the PC
      blockAddress = pc_ & blockMask_;
      bufferOffset = pc_ - blockAddress;
    }

    std::cout << "get completed read" << std::endl;

    // Find fetched memory that matches the desired block
    const auto& fetched = instructionMemory_.getCompletedReads();

    size_t fetchIndex;
    for (fetchIndex = 0; fetchIndex < fetched.size(); fetchIndex++) {
      if (fetched[fetchIndex].target.address == blockAddress) {
        break;
      }
    }
    if (fetchIndex == fetched.size() &&
        bufferedBytes_ < isa_.getMinInstructionSize()) {
      std::cout << "need to wait" << std::endl;

      // Need to wait for fetched instructions
      return;
    } else if (fetchIndex == fetched.size()) {
      std::cout << "new case" << std::endl;

      // There is minimal data already in the buffer which may be predecodable
      // and no new data has been supplied

      // Do nothing and allow continuation
    } else {
      std::cout << "Move data into fetch buffer" << std::endl;

      // Data has been successfully read, move into fetch buffer
      // TODO: Handle memory faults
      assert(fetched[fetchIndex].data && "Memory read failed");
      const uint8_t* fetchData =
          fetched[fetchIndex].data.getAsVector<uint8_t>();

      // Copy fetched data to fetch buffer after existing data
      std::memcpy(fetchBuffer_ + bufferedBytes_, fetchData + bufferOffset,
                  blockSize_ - bufferOffset);

      bufferedBytes_ += blockSize_ - bufferOffset;
      buffer = fetchBuffer_;
      // Decoding should start from the beginning of the fetchBuffer_.
      bufferOffset = 0;
    }
  } else {
    // There is already enough data in the fetch buffer, so use that
    buffer = fetchBuffer_;
    bufferOffset = 0;
  }

  std::cout << "get min size" << std::endl;

  // Check we have enough data to begin decoding as read may not have completed
  if (bufferedBytes_ < isa_.getMinInstructionSize()) return;

  auto outputSlots = output_.getTailSlots();
  for (size_t slot = 0; slot < output_.getWidth(); slot++) {
    auto& macroOp = outputSlots[slot];

    std::cout << "predecode" << std::endl;

    auto bytesRead =
        isa_.predecode(buffer + bufferOffset, bufferedBytes_, pc_, macroOp);

    // If predecode fails, bail and wait for more data
    if (bytesRead == 0) {
      assert(bufferedBytes_ < isa_.getMaxInstructionSize() &&
             "unexpected predecode failure");
      break;
    }

    // Create branch prediction after identifying instruction type
    // (e.g. RET, BL, etc).
    BranchPrediction prediction = {false, 0};
    if (macroOp[0]->isBranch()) {
      prediction = branchPredictor_.predict(pc_, macroOp[0]->getBranchType(),
                                            macroOp[0]->getKnownOffset());
      macroOp[0]->setBranchPrediction(prediction);
    }

    if (loopBufferState_ == LoopBufferState::FILLING) {
      // Record instruction fetch information in loop body
      uint32_t encoding;
      memcpy(&encoding, buffer + bufferOffset, sizeof(uint32_t));
      loopBuffer_.push_back(
          {encoding, bytesRead, pc_, macroOp[0]->getBranchPrediction()});

      if (pc_ == loopBoundaryAddress_) {
        if (macroOp[0]->isBranch() &&
            !macroOp[0]->getBranchPrediction().taken) {
          // loopBoundaryAddress_ has been fetched whilst filling the loop
          // buffer BUT this is a branch, predicted to branch out of the loop
          // being buffered. Stop filling the loop buffer and don't supply to
          // decode
          loopBufferState_ = LoopBufferState::IDLE;
        } else {
          // loopBoundaryAddress_ has been fetched whilst filling the loop
          // buffer. Stop filling as loop body has been recorded and begin to
          // supply decode unit with instructions from the loop buffer
          loopBufferState_ = LoopBufferState::SUPPLYING;
          bufferedBytes_ = 0;
          break;
        }
      }
    } else if (loopBufferState_ == LoopBufferState::WAITING &&
               pc_ == loopBoundaryAddress_) {
      // Once set loopBoundaryAddress_ is fetched, start to fill loop buffer
      loopBufferState_ = LoopBufferState::FILLING;
    }

    assert(bytesRead <= bufferedBytes_ &&
           "Predecode consumed more bytes than were available");

    // Increment the offset, decrement available bytes
    bufferOffset += bytesRead;
    bufferedBytes_ -= bytesRead;

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
      bufferedBytes_ = 0;
      break;
    }

    // Too few bytes remaining in buffer to continue
    if (bufferedBytes_ == 0) {
      break;
    }
  }

  if (bufferedBytes_ > 0) {
    // Move start of fetched data to beginning of fetch buffer
    std::memmove(fetchBuffer_, buffer + bufferOffset, bufferedBytes_);
  }

  instructionMemory_.clearCompletedReads();

  std::cout << "end of tick, bufferedBytes=" << (int)bufferedBytes_
            << " pc=" << pc_ << std::endl;
}

void FetchUnit::registerLoopBoundary(uint64_t branchAddress) {
  // Set branch which forms the loop as the loopBoundaryAddress_ and place loop
  // buffer in state to begin filling once the loopBoundaryAddress_ has been
  // fetched
  loopBufferState_ = LoopBufferState::WAITING;
  loopBoundaryAddress_ = branchAddress;
}

bool FetchUnit::hasHalted() const { return hasHalted_; }

void FetchUnit::updatePC(uint64_t address) {
  pc_ = address;
  bufferedBytes_ = 0;
  hasHalted_ = (pc_ >= programByteLength_);
}

void FetchUnit::requestFromPC() {
  // Do nothing if supplying fetch stream from loop buffer
  if (loopBufferState_ == LoopBufferState::SUPPLYING) return;

  // Do nothing if buffer already contains enough data
  if (bufferedBytes_ >= isa_.getMaxInstructionSize()) return;

  // Do nothing if unit has halted to avoid invalid speculative memory reads
  // beyond the programByteLength_
  if (hasHalted_) return;

  uint64_t blockAddress;
  if (bufferedBytes_ > 0) {
    // There's already some data in the buffer, so fetch the next block
    blockAddress = pc_ + bufferedBytes_;
    assert((blockAddress & ~blockMask_) == 0 && "misaligned fetch buffer");
  } else {
    // Fetch buffer is empty, so fetch from the PC
    blockAddress = pc_ & blockMask_;
  }

  instructionMemory_.requestRead({blockAddress, blockSize_});
}

uint64_t FetchUnit::getBranchStalls() const { return branchStalls_; }

void FetchUnit::flushLoopBuffer() {
  loopBuffer_.clear();
  loopBufferState_ = LoopBufferState::IDLE;
  loopBoundaryAddress_ = 0;
}

}  // namespace pipeline
}  // namespace simeng
