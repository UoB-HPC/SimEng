#include "simeng/pipeline/FetchUnit.hh"

namespace simeng {
namespace pipeline {

FetchUnit::FetchUnit(PipelineBuffer<MacroOp>& output,
                     std::shared_ptr<memory::MMU> mmu, uint8_t blockSize,
                     arch::Architecture& isa, BranchPredictor& branchPredictor)
    : output_(output),
      mmu_(mmu),
      isa_(isa),
      branchPredictor_(branchPredictor),
      blockSize_(blockSize),
      blockMask_(~(blockSize_ - 1)) {
  assert(blockSize_ >= isa_.getMaxInstructionSize() &&
         "fetch block size must be larger than the largest instruction");
  // mopCache_ = std::vector<std::pair<RegisterValue, uint64_t>>(
  //     static_cast<uint64_t>(1 << mopCacheTagBits_), {{}, 0ull});
}

FetchUnit::~FetchUnit() {}

void FetchUnit::tick() {
  tickcounter_++;
  if (fetchPrint_) std::cerr << "=== " << tickcounter_ << " ===" << std::endl;

  // Get any instruction memory reads
  const auto& fetched = mmu_->getCompletedInstrReads();

  // Check if any fetched instruction blocks have registered requests
  for (const auto& blk : fetched) {
    auto it = std::find(requestedBlocks_.begin(), requestedBlocks_.end(),
                        blk.target.vaddr);
    if (fetchPrint_)
      std::cerr << "Got I block " << std::hex << blk.target.vaddr << std::dec
                << std::endl;
    if (it != requestedBlocks_.end()) {
      // If the block has been requested, pre-decode all possible instructions
      // in block
      uint64_t address = blk.target.vaddr;
      // Get mop cache index
      uint64_t cacheIndex = address & ((1 << mopCacheTagBits_) - 1);
      // mopCache_[cacheIndex].second = address;
      if (blk.data.size()) {
        // const uint8_t* fetchData = blk.data.getAsVector<uint8_t>();
        // uint16_t dataOffset = 0;

        // while (dataOffset < blk.target.size) {
        //   memcpy(&mopCache_[cacheIndex].first, (fetchData + dataOffset), 4);
        for (uint64_t i = address; i < (address + blk.data.size()); i += 4) {
          mopCache_[i] = blk.data.getAsVector<uint32_t>()[(i - address) / 4];
          // if (fetchPrint_)
          //   std::cerr << "\tStored " << std::hex << i << std::dec << " ("
          //             << (i - address) / 4 << ")" << std::endl;
        }
        //   // Increment the offset and address
        //   dataOffset += static_cast<uint16_t>(4);
        //   address += static_cast<uint64_t>(4);
        // }
      }
      // else {
      //   // Create zero'ed out block if no data was read
      //   // char* zeroBlock = (char*)calloc(blk.target.size, sizeof(char));
      //   // mopCache_[cacheIndex].first = RegisterValue(zeroBlock,
      //   // blk.target.size);
      //   for (int i = address; i < address + blk.data.size(); i += 4)
      //     mopCache_[i] = 0;
      //   // mopCache_.push_back(
      //   //     {RegisterValue(zeroBlock, blk.target.size), address});
      //   if (fetchPrint_) std::cerr << "\tZero Data" << std::endl;
      //   // free(zeroBlock);
      // }
      uint64_t latVal = tickcounter_ - reqBlkLats_[*it];
      if (l1ILats_.find(latVal) == l1ILats_.end()) {
        l1ILats_[latVal] = 0;
      }
      l1ILats_[latVal]++;

      reqBlkLats_.erase(*it);
      requestedBlocks_.erase(it);
    } else {
      if (fetchPrint_) std::cerr << "\tThrown" << std::endl;
    }
  }
  mmu_->clearCompletedIntrReads();

  if (output_.isStalled() || paused_) {
    // if (fetchPrint_)
    //   std::cerr << (output_.isStalled() ? "Stalled" : "Paused")
    //             << " so no fetch " << std::endl;
    return;
  }

  if (hasHalted_) {
    return;
  }

  bool sentBlock = false;

  if (branchDelayed_.size() && branchDelayed_.front().second < tickcounter_) {
    mmu_->requestInstrRead(
        {branchDelayed_.front().first, blockSize_, requestedBlockId_++});
    branchDelayed_.pop_front();
  }
  // if (requestBranchTargetBlock_ != -1) {
  //   // Request new block from instruction memory if there isn't an existing
  //   // request
  //   auto it = std::find(requestedBlocks_.begin(), requestedBlocks_.end(),
  //                       requestBranchTargetBlock_);
  //   if (it == requestedBlocks_.end()) {
  //     if (fetchPrint_)
  //       std::cerr << "\tRequesting branch target block: " << std::hex
  //                 << requestBranchTargetBlock_ << std::dec << std::endl;
  //     mmu_->requestInstrRead(
  //         {requestBranchTargetBlock_, blockSize_, requestedBlockId_++});
  //     requestedBlocks_.push_back(requestBranchTargetBlock_);
  //   }
  //   requestBranchTargetBlock_ = -1;
  // }
  // Determine if there's space in the mop queue
  while (mopQueue_.size() < mopQueueSize_) {
    // Determine if cached entry is correct
    uint64_t blockAddress = pc_ & blockMask_;
    // uint64_t cacheIndex = blockAddress & ((1 << mopCacheTagBits_) - 1);
    // if (cachedEntry.first.size() != 0 &&
    //     (cachedEntry.second == blockAddress)) {
    // auto mopItr = mopCache_.begin();
    // while (mopItr != mopCache_.end()) {
    //   if (mopItr->second == blockAddress) break;
    //   mopItr++;
    // }
    // if (mopItr != mopCache_.end()) {
    if (mopCache_.find(pc_) != mopCache_.end()) {
      // std::pair<RegisterValue, uint64_t> cachedEntry = *mopItr;
      mopQueue_.push_back({});
      auto& macroOp = mopQueue_.back();

      uint8_t bytesRead = 0;
      if (fetchPrint_) {
        std::cerr << "Fetching PC " << std::hex << pc_ << std::dec << "("
                  << mopQueue_.size() << ")" << std::endl;
        // std::cerr << "\tChecking for cross on block " << std::hex
        //           << blockAddress << std::dec << ": "
        //           << (blockAddress + blockSize_) - pc_ << std::endl;
      }
      // if ((blockAddress + blockSize_) - pc_ < 4) {
      //   uint64_t blockAddress2 = (pc_ + blockSize_) & blockMask_;
      //   if (fetchPrint_)
      //     std::cerr << "\tCrosses, trying to find block " << std::hex
      //               << blockAddress2 << std::dec << std::endl;
      //   // uint64_t cacheIndex2 = blockAddress2 & ((1 << mopCacheTagBits_)
      //   -
      //   // 1);
      //   // std::pair<RegisterValue, uint64_t> cachedEntry2 =
      //   //     mopCache_[cacheIndex2];

      //   // if (cachedEntry2.first.size() != 0 &&
      //   //     (cachedEntry2.second == blockAddress2)) {
      //   auto mopCrossItr = mopCache_.begin();
      //   while (mopCrossItr != mopCache_.end()) {
      //     if (mopCrossItr->second == blockAddress2) break;
      //     mopCrossItr++;
      //   }
      //   if (mopCrossItr != mopCache_.end()) {
      //     std::pair<RegisterValue, uint64_t> cachedEntry2 = *mopCrossItr;
      //     if (fetchPrint_)
      //       std::cerr << "\tGot second block: " << std::hex
      //                 << (*cachedEntry2.first.getAsVector<uint8_t>() +
      //                     ((pc_ + blockSize_) - blockAddress2))
      //                 << std::dec << " -> " << std::hex
      //                 << (((*cachedEntry2.first.getAsVector<uint8_t>() +
      //                       ((pc_ + blockSize_) - blockAddress2)) &
      //                      0xFFFF)
      //                     << 16)
      //                 << std::dec << " | " << std::hex
      //                 << (*cachedEntry.first.getAsVector<uint8_t>() +
      //                     (pc_ - blockAddress))
      //                 << std::dec << " -> " << std::hex
      //                 << ((*cachedEntry.first.getAsVector<uint8_t>() +
      //                      (pc_ - blockAddress)) &
      //                     0xFFFF)
      //                 << std::dec << std::endl;

      //     uint64_t boundaryCrossedBytes =
      //         (static_cast<uint64_t>(
      //              *(cachedEntry2.first.getAsVector<uint8_t>() +
      //                ((blockAddress2 + 1) - blockAddress2)))
      //          << 24) |
      //         (static_cast<uint64_t>(
      //              *(cachedEntry2.first.getAsVector<uint8_t>() +
      //                ((blockAddress2)-blockAddress2)))
      //          << 16) |
      //         (static_cast<uint64_t>(
      //              *(cachedEntry.first.getAsVector<uint8_t>() +
      //                (pc_ + 1 - blockAddress)))
      //          << 8) |
      //         (static_cast<uint64_t>(
      //             *(cachedEntry.first.getAsVector<uint8_t>() +
      //               (pc_ - blockAddress))));

      //     if (fetchPrint_)
      //       std::cerr
      //           << "\t" << std::hex
      //           << unsigned((static_cast<uint64_t>(
      //                            *(cachedEntry2.first.getAsVector<uint8_t>()
      //                            +
      //                              ((blockAddress2 + 1) - blockAddress2)))
      //                        << 24))
      //           << std::dec << ":" << std::hex
      //           << unsigned((static_cast<uint64_t>(
      //                            *(cachedEntry2.first.getAsVector<uint8_t>()
      //                            +
      //                              ((blockAddress2)-blockAddress2)))
      //                        << 16))
      //           << std::dec << ":" << std::hex
      //           << unsigned((static_cast<uint64_t>(
      //                            *(cachedEntry.first.getAsVector<uint8_t>()
      //                            +
      //                              (pc_ + 1 - blockAddress)))
      //                        << 8))
      //           << std::dec << ":" << std::hex
      //           << unsigned((static_cast<uint64_t>(
      //                  *(cachedEntry.first.getAsVector<uint8_t>() +
      //                    (pc_ - blockAddress)))))
      //           << std::dec << " = " << std::hex << boundaryCrossedBytes
      //           << std::dec << std::endl;

      //     bytesRead = isa_.predecode(&boundaryCrossedBytes, 4, pc_,
      //     macroOp);
      //   } else {
      //     // Request new block from instruction memory if there isn't an
      //     // existing request
      //     mopQueue_.pop_back();
      //     auto it = std::find(requestedBlocks_.begin(),
      //                         requestedBlocks_.end(), blockAddress2);
      //     if (it == requestedBlocks_.end()) {
      //       mmu_->requestInstrRead(
      //           {blockAddress2, blockSize_, requestedBlockId_++});
      //       requestedBlocks_.push_back(blockAddress2);
      //     }
      //     break;
      //   }
      // } else {
      bytesRead = isa_.predecode(
          // cachedEntry.first.getAsVector<uint8_t>() + (pc_ -
          // blockAddress),
          mopCache_.at(pc_).getAsVector<uint8_t>(), 4, pc_, macroOp);
      // insnsBetweenTaken_++;
      // }

      // If predecode fails, bail and wait for more data
      if (bytesRead == 0) {
        mopQueue_.pop_back();
        break;
      }

      if (bytesRead == 100) {
        mopQueue_.pop_back();
        pc_ += 4;
        continue;
      }

      // Create branch prediction after identifying instruction type
      // (e.g. RET, BL, etc).
      BranchPrediction prediction = {false,
                                     pc_ + static_cast<uint64_t>(bytesRead)};
      if (macroOp[0]->isBranch()) {
        prediction = branchPredictor_.predict(pc_, macroOp[0]->getBranchType(),
                                              macroOp[0]->getKnownOffset());

        if (fetchPrint_)
          std::cerr << "[SimEng] Predicted " << std::hex << pc_ << std::dec
                    << " - " << macroOp[0]->getInstructionId()
                    << " with Target: " << std::hex << prediction.target
                    << std::dec << " and Direction: " << prediction.isTaken
                    << std::endl;
        branchesFetched_++;
      }
      macroOp[0]->setBranchPrediction(prediction);

      if (sctpCntr_ < 4) mopCache_.erase(pc_);

      // Update PC based on previous branch prediction
      if (prediction.isTaken) {
        if (std::find(stcp_.begin(), stcp_.end(),
                      std::pair<uint64_t, uint64_t>(
                          {pc_, prediction.target})) != stcp_.end()) {
          sctpCntr_++;
          if (fetchPrint_) {
            std::cerr << "[SimEng] sct cntr at " << sctpCntr_ << std::endl;
            if (sctpCntr_ == 4) {
              std::cerr << "[SimEng]\tIdentified sct with branches ";
              for (const auto& bp : stcp_)
                std::cerr << "{" << std::hex << bp.first << std::dec << ", "
                          << std::hex << bp.second << std::dec << "}, ";
              std::cerr << "\b\b" << std::endl;
            }
          }
        } else {
          stcp_.push_back({pc_, prediction.target});
          while (stcp_.size() > 4) stcp_.pop_front();
          if (fetchPrint_ && sctpCntr_ >= 4) {
            std::cerr << "[SimEng] Cleared sct" << std::endl;
          }
          sctpCntr_ = 0;
        }

        // Predicted as taken; set PC to predicted target address
        // if (shortLoopTracker_.first == pc_) {
        //   if (insnsBetweenTaken_ <= 48)
        //     shortLoopTracker_.second++;
        //   else
        //     shortLoopTracker_.second = 1;
        // } else {
        //   shortLoopTracker_ = {pc_, 1};
        // }
        pc_ = prediction.target;
        // requestBranchTargetBlock_ = pc_ & blockMask_;
        // pausedUntil_ = tickcounter_ + 3;
        // insnsBetweenTaken_ = 0;
        // if (pc_ == 0x212454) fetchPrint_ = true;
        // break;
      } else {
        // Predicted as not taken; increment PC to next instruction
        pc_ += bytesRead;
        // if (pc_ == 0x212454) fetchPrint_ = true;
      }
    } else {
      // Request new block from instruction memory if there isn't an existing
      // request
      auto it = std::find(requestedBlocks_.begin(), requestedBlocks_.end(),
                          blockAddress);
      if (it == requestedBlocks_.end()) {
        // requestedBlocks_.clear();
        runAheadPC_ = pc_ + 4;
        if (fetchPrint_)
          std::cerr << "\tRequesting pc_ block: " << std::hex << blockAddress
                    << std::dec << " for " << std::hex << pc_ << std::dec
                    << std::endl;
        mmu_->requestInstrRead({blockAddress, blockSize_, requestedBlockId_++});
        requestedBlocks_.push_back(blockAddress);
        reqBlkLats_[blockAddress] = tickcounter_;
        if (sctpCntr_ < 4) mopCache_.clear();
        fetchStalls_++;
        sentBlock = true;
      }
      break;
    }
  }
  // if (shortLoopTracker_.second < 3) mopCache_.clear();
  // }

  if (!sentBlock && (mopCache_.size() + requestedBlocks_.size() * 8) < 48 &&
      sctpCntr_ < 5) {
    uint64_t nextBlock = (runAheadPC_ + 32) & blockMask_;
    uint64_t bpAddr = 0;
    BranchPrediction pred = {false, 0};
    for (uint64_t i = runAheadPC_; i < ((runAheadPC_ + 32) & blockMask_);
         i += 4) {
      pred = branchPredictor_.predict(i);
      if (pred.isTaken) {
        bpAddr = i;
        nextBlock = pred.target & blockMask_;
        break;
      }
    }

    auto it =
        std::find(requestedBlocks_.begin(), requestedBlocks_.end(), nextBlock);
    if (it == requestedBlocks_.end()) {
      if (nextBlock == ((runAheadPC_ + 32) & blockMask_)) {
        if (fetchPrint_)
          std::cerr << "\tRequesting contiguous block: " << std::hex
                    << nextBlock << std::dec << std::endl;

        mmu_->requestInstrRead({nextBlock, blockSize_, requestedBlockId_++});
      } else {
        if (fetchPrint_)
          std::cerr << "\tRequesting non-contiguous block: " << std::hex
                    << nextBlock << std::dec << " for " << std::hex
                    << pred.target << std::dec << " by " << std::hex << bpAddr
                    << std::dec << std::endl;
        // pausedUntil_ = tickcounter_ + 3;
        branchDelayed_.push_back({nextBlock, tickcounter_ + 3});
      }

      requestedBlocks_.push_back(nextBlock);
      reqBlkLats_[nextBlock] = tickcounter_;
      runAheadPC_ =
          pred.isTaken ? pred.target : (runAheadPC_ + 32) & blockMask_;
    }
  }

  // Send mops to decode unit up to the width of the buffer
  uint16_t idx = 0;
  bool earlyBreak = false;
  while (mopQueue_.size() && idx < output_.getWidth()) {
    // if (mopQueue_.front().size() > 2) {
    //   if (idx != 0) break;
    //   earlyBreak = true;
    // }
    // if (mopQueue_.front()[0]->getBranchPrediction().isTaken) earlyBreak =
    // true;

    for (int i = 0; i < mopQueue_.front().size(); i++) {
      if (fetchPrint_)
        std::cerr << "\tPass: " << std::hex
                  << mopQueue_.front()[i]->getInstructionAddress() << std::dec
                  << ":" << mopQueue_.front()[i]->getSequenceId() << ":"
                  << mopQueue_.front()[i]->getOpcode() << std::endl;
      output_.getTailSlots()[idx].push_back(std::move(mopQueue_.front()[i]));
    }
    if (earlyBreak) {
      mopQueue_.pop_front();
      break;
    }

    idx++;
    mopQueue_.pop_front();
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
  paused_ = false;
  // if (mmu_->getTid() == 24)
  if (fetchPrint_)
    std::cerr << "Updating PC from " << std::hex << pc_ << std::dec << " to "
              << std::hex << address << std::dec << std::endl;
  pc_ = address;
  runAheadPC_ = pc_ + 4;
  // requestedBlocks_.clear();
  // requestBranchTargetBlock_ = -1;

  for (const auto& insn : mopQueue_) {
    if (insn[0]->isBranch())
      branchPredictor_.flush(insn[0]->getInstructionAddress());
  }
  mopQueue_.clear();
  mopCache_.clear();
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

uint64_t FetchUnit::getBranchFetchedCount() const { return branchesFetched_; }

void FetchUnit::flushLoopBuffer() {
  loopBuffer_.clear();
  loopBufferState_ = LoopBufferState::IDLE;
  loopBoundaryAddress_ = 0;
}

}  // namespace pipeline
}  // namespace simeng
