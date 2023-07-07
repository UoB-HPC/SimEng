#include "simeng/pipeline/FetchUnit.hh"

namespace simeng {
namespace pipeline {

FetchUnit::FetchUnit(PipelineBuffer<MacroOp>& output,
                     std::shared_ptr<memory::MMU> mmu, uint8_t blockSize,
                     const arch::Architecture& isa,
                     BranchPredictor& branchPredictor)
    : output_(output),
      mmu_(mmu),
      isa_(isa),
      branchPredictor_(branchPredictor),
      blockSize_(blockSize),
      blockMask_(~(blockSize_ - 1)) {
  assert(blockSize_ >= isa_.getMaxInstructionSize() &&
         "fetch block size must be larger than the largest instruction");
}

FetchUnit::~FetchUnit() {}

void FetchUnit::tick() {
  if (programByteLength_ == 0) {
    std::cerr
        << "[SimEng::FetchUnit] Invalid Program Byte Length of 0. Please "
           "ensure setProgramLength() is called before calling updatePC().\n";
    exit(1);
  }

  if (output_.isStalled() || hasHalted_ || paused_) {
    return;
  }

  // If loop buffer has been filled, fill buffer to decode
  if (loopBufferState_ == LoopBufferState::SUPPLYING) {
    auto outputSlots = output_.getTailSlots();
    // Fill the macrop op buffer to match the fetch units output rate
    while (mOpBuffer_.size() < output_.getWidth()) {
      mOpBuffer_.push_back(MacroOp());
      auto bytesRead = isa_.predecode(
          &(loopBuffer_.front().encoding), loopBuffer_.front().instructionSize,
          loopBuffer_.front().address, mOpBuffer_.back());

      assert(bytesRead != 0 && "predecode failure for loop buffer entry");

      // Set prediction to recorded value during loop buffer filling
      if (mOpBuffer_.back()[0]->isBranch()) {
        mOpBuffer_.back()[0]->setBranchPrediction(
            loopBuffer_.front().prediction);
      }

      // Cycle queue by moving front entry to back
      loopBuffer_.push_back(loopBuffer_.front());
      loopBuffer_.pop_front();
      // Update PC to address of next instruction in buffer to maintain correct
      // PC value
      pc_ = loopBuffer_.front().address;
    }
  } else {
    // Add any newly fetched block to the requestedBlocks_ map if an entry has
    // been reserved
    const auto& fetched = mmu_->getCompletedInstrReads();
    size_t fetchIndex;
    for (fetchIndex = 0; fetchIndex < fetched.size(); fetchIndex++) {
      // Check for data
      if (!fetched[fetchIndex].data) continue;

      // Check for entry in requestedBlocks_
      uint64_t blockVaddr = fetched[fetchIndex].target.vaddr;
      if (requestedBlocks_.find(blockVaddr) == requestedBlocks_.end()) {
        continue;
      }

      requestedBlocks_[blockVaddr].data =
          std::vector<uint8_t>(fetched[fetchIndex].data.getAsVector<uint8_t>(),
                               fetched[fetchIndex].data.getAsVector<uint8_t>() +
                                   fetched[fetchIndex].data.size());
    }
    mmu_->clearCompletedIntrReads();

    // Fill mOpBuffer_ with data from fetched blocks
    uint8_t* mOpPtr = nullptr;
    while (mOpBuffer_.size() < 48) {
      uint64_t pcBlock_ = pc_ & blockMask_;

      // If the pc is not contained within any fetched blocks, fetch a new one
      if (requestedBlocks_.find(pcBlock_) == requestedBlocks_.end()) {
        // If there are no spare entries in the requestedBlocks_ maps, replace
        // the least recently used one
        if (requestedBlocks_.size() >= 6) {
          uint64_t entryToRemove = 0;
          uint64_t oldestCount = 0;
          auto it = requestedBlocks_.begin();
          for (; it != requestedBlocks_.end(); it++) {
            if (it->second.cyclesSinceUse > oldestCount)
              entryToRemove = it->first;
          }
          requestedBlocks_.erase(entryToRemove);
        }
        requestedBlocks_[pcBlock_] = {{}, 0};
        mmu_->requestInstrRead({pcBlock_, blockSize_});
        break;
      }

      // If the data for the fetch block is yet to be retrieved, wait
      if (requestedBlocks_[pcBlock_].data.size() == 0) {
        break;
      }

      // Reset replacement policy value
      requestedBlocks_[pcBlock_].cyclesSinceUse = 0;

      // Decode an instruction based on data within the selected fetch block
      mOpBuffer_.push_back(MacroOp());
      mOpPtr = requestedBlocks_[pcBlock_].data.data();
      size_t byteIndex = pc_ - pcBlock_;
      auto bytesRead =
          isa_.predecode(mOpPtr + byteIndex,
                         requestedBlocks_[pcBlock_].data.size() - byteIndex,
                         pc_, mOpBuffer_.back());

      // If the decode failed, remove entry in macro op buffer and retry
      if (bytesRead == 0) {
        mOpBuffer_.pop_back();
        continue;
      }

      // Create branch prediction after identifing instruction type
      // (e.g. RET, BL, etc).
      BranchPrediction prediction = {false, 0};
      if (mOpBuffer_.back()[0]->isBranch()) {
        prediction =
            branchPredictor_.predict(pc_, mOpBuffer_.back()[0]->getBranchType(),
                                     mOpBuffer_.back()[0]->getKnownOffset());
        mOpBuffer_.back()[0]->setBranchPrediction(prediction);
      }

      if (loopBufferState_ == LoopBufferState::FILLING) {
        // Record instruction fetch information in loop body
        uint32_t encoding;
        memcpy(&encoding, mOpPtr + byteIndex, sizeof(uint32_t));
        loopBuffer_.push_back({encoding, bytesRead, pc_,
                               mOpBuffer_.back()[0]->getBranchPrediction()});

        if (pc_ == loopBoundaryAddress_) {
          // loopBoundaryAddress_ has been fetched whilst filling the loop
          // buffer. Stop filling as loop body has been recorded and begin to
          // supply decode unit with instructions from the loop buffer
          loopBufferState_ = LoopBufferState::SUPPLYING;
          break;
        }
      } else if (loopBufferState_ == LoopBufferState::WAITING &&
                 pc_ == loopBoundaryAddress_) {
        // Once set loopBoundaryAddress_ is fetched, start to fill loop buffer
        loopBufferState_ = LoopBufferState::FILLING;
      }

      if (!prediction.taken) {
        // Predicted as not taken; increment PC to next instruction
        pc_ += bytesRead;
      } else {
        // Predicted as taken; set PC to predicted target address
        pc_ = prediction.target;
      }

      // Break loop if the pc surpasses the program byte length
      if (pc_ >= programByteLength_) {
        hasHalted_ = true;
        break;
      }
    }
  }

  // Work through macro op buffer and send to output buffer
  auto outputSlots = output_.getTailSlots();
  for (size_t slot = 0; slot < output_.getWidth(); slot++) {
    if (mOpBuffer_.size()) {
      outputSlots[slot] = mOpBuffer_.front();
      mOpBuffer_.pop_front();
    } else {
      fetchStalls_++;
      break;
    }
  }

  // Update replacement policy variables
  auto it = requestedBlocks_.begin();
  for (; it != requestedBlocks_.end(); it++) {
    if (it->second.data.size()) it->second.cyclesSinceUse++;
  }
}

void FetchUnit::registerLoopBoundary(uint64_t branchAddress) {
  // Set branch which forms the loop as the loopBoundaryAddress_ and place
  // loop buffer in state to begin filling once the loopBoundaryAddress_ has
  // been fetched
  loopBufferState_ = LoopBufferState::WAITING;
  loopBoundaryAddress_ = branchAddress;
}

bool FetchUnit::hasHalted() const { return hasHalted_; }

void FetchUnit::updatePC(uint64_t address) {
  pc_ = address;
  mOpBuffer_.clear();
  if (programByteLength_ == 0) {
    std::cerr
        << "[SimEng::FetchUnit] Invalid Program Byte Length of 0. Please "
           "ensure setProgramLength() is called before calling updatePC().\n";
    exit(1);
  }
  hasHalted_ = (pc_ >= programByteLength_);
}

void FetchUnit::setProgramLength(uint64_t size) { programByteLength_ = size; }

uint64_t FetchUnit::getFetchStalls() const { return fetchStalls_; }

void FetchUnit::flushLoopBuffer() {
  loopBuffer_.clear();
  loopBufferState_ = LoopBufferState::IDLE;
  loopBoundaryAddress_ = 0;
}

}  // namespace pipeline
}  // namespace simeng
