#include "simeng/pipeline/ReorderBuffer.hh"

#include <algorithm>
#include <cassert>
#include <iostream>

namespace simeng {
namespace pipeline {

ReorderBuffer::ReorderBuffer(
    unsigned int maxSize, RegisterAliasTable& rat, LoadStoreQueue& lsq,
    std::function<void(const std::shared_ptr<Instruction>&)> raiseException,
    std::function<void(uint64_t branchAddress)> sendLoopBoundary,
    BranchPredictor& predictor, uint16_t loopBufSize,
    uint16_t loopDetectionThreshold)
    : rat_(rat),
      lsq_(lsq),
      maxSize_(maxSize),
      raiseException_(raiseException),
      sendLoopBoundary_(sendLoopBoundary),
      predictor_(predictor),
      loopBufSize_(loopBufSize),
      loopDetectionThreshold_(loopDetectionThreshold) {}

void ReorderBuffer::reserve(const std::shared_ptr<Instruction>& insn) {
  assert(buffer_.size() < maxSize_ &&
         "Attempted to reserve entry in reorder buffer when already full");

  buffer_.push_back(insn);
}

void ReorderBuffer::commitMicroOps(uint64_t insnId) {
  if (buffer_.size()) {
    size_t index = 0;
    int firstOp = -1;
    bool validForCommit = false;

    // Find first instance of uop belonging to macro-op instruction
    for (; index < buffer_.size(); index++) {
      if (buffer_[index]->getInstructionId() == insnId) {
        firstOp = index;
        break;
      }
    }

    if (firstOp > -1) {
      // If found, see if all uops are committable
      for (; index < buffer_.size(); index++) {
        if (buffer_[index]->getInstructionId() != insnId) break;
        if (!buffer_[index]->isWaitingCommit()) {
          return;
        } else if (buffer_[index]->isLastMicroOp()) {
          // all microOps must be in ROB for the commit to be valid
          validForCommit = true;
        }
      }
      if (!validForCommit) return;

      // No early return thus all uops are committable
      for (; firstOp < buffer_.size(); firstOp++) {
        if (buffer_[firstOp]->getInstructionId() != insnId) break;
        buffer_[firstOp]->setCommitReady();
      }
    }
  }
  return;
}

unsigned int ReorderBuffer::commit(unsigned int maxCommitSize) {
  shouldFlush_ = false;
  size_t maxCommits =
      std::min(static_cast<size_t>(maxCommitSize), buffer_.size());

  unsigned int n = 0;
  for (; n < maxCommits; n++) {
    auto& uop = buffer_.front();

    if (uop->exceptionEncountered()) {
      // std::cerr << "Raise exception on " << std::hex
      //           << uop->getInstructionAddress() << std::dec << ":"
      //           << uop->getSequenceId() << std::endl;
      raiseException_(uop);
      buffer_.pop_front();
      return n + 1;
    }

    // Process atomics & Load-Reserved once they reach front of ROB
    if (!sentAtomic_ && (uop->isLoad()) &&
        (uop->isLoadReserved() || uop->isAtomic())) {
      if (uop->getGeneratedAddresses().size() > 0) {
        lsq_.startLoad(uop);
        sentAtomic_ = true;
      }
      // Early return so load can be processed
      return n;
    }

    if (!uop->canCommit()) {
      break;
    }

    // If the uop is a store address operation, begin the processing of its
    // memory accesses
    if (uop->isStoreAddress() && !startedStore_) {
      // Only try to start the store if there are addresses to be stored at
      if (uop->getGeneratedAddresses().size() != 0) {
        lsq_.startStore(uop);
        startedStore_ = true;
        // Reset store's commit ready status as we need to determine any
        // post-memory-request values to be committed
        uop->setCommitReady(false);
        return n;
      }
    }

    if (uop->isLastMicroOp()) {
      instructionsCommitted_++;
    }
    // if (tid_ == 3) {
    //   std::cerr << tid_ << "|" << std::hex << uop->getInstructionAddress()
    //             << std::dec << ":" << std::hex << uop->getSequenceId()
    //             << std::dec << std::endl;
    // }

    const auto& destinations = uop->getDestinationRegisters();

    // if (tid_ == 6) {
    if (false) {
      // if (fileOut_.is_open()) {
      const auto& results = uop->getResults();
      fileOut_ << tid_ << "|" << std::hex << uop->getInstructionAddress()
               << std::dec;
      fileOut_ << ":0x" << std::hex << uop->getSequenceId() << std::dec;
      fileOut_ << std::endl;
      for (int i = 0; i < destinations.size(); i++) {
        fileOut_ << tid_ << "|\t{" << unsigned(destinations[i].type) << ":"
                 << rat_.reverseMapping(destinations[i]) << "}"
                 << " <- " << std::hex;
        for (int j = results[i].size() - 1; j >= 0; j--) {
          fileOut_ << unsigned(results[i].getAsVector<uint8_t>()[j]);
        }
        fileOut_ << std::dec << std::endl;
      }

      if (uop->isLoad()) {
        const auto& addrs = uop->getGeneratedAddresses();
        for (int i = 0; i < addrs.size(); i++) {
          fileOut_ << tid_ << "|\tAddr " << std::hex << addrs[i].vaddr
                   << std::dec << std::endl;
        }
      }
      if (uop->isStoreAddress()) {
        const auto& addrs = uop->getGeneratedAddresses();
        const auto& data = uop->getData();

        for (int i = 0; i < addrs.size(); i++) {
          fileOut_ << tid_ << "|\tAddr " << std::hex << addrs[i].vaddr
                   << std::dec << " <- " << std::hex;
          for (int j = data[i].size() - 1; j >= 0; j--) {
            fileOut_ << unsigned(data[i].getAsVector<uint8_t>()[j]);
          }
          fileOut_ << std::dec << std::endl;
        }
      }
    }

    for (int i = 0; i < destinations.size(); i++) {
      rat_.commit(destinations[i]);
    }

    // If it's a memory op, commit the entry at the head of the respective
    // queue
    if (uop->isLoad()) {
      numLoads_++;
      lsq_.commitLoad(uop);
      // TODO: If aqcuire, flush
    }
    if (uop->isStoreAddress()) {
      numStores_++;
      startedStore_ = false;
      bool violationFound = lsq_.commitStore(uop);
      if (violationFound) {
        loadViolations_++;
        // Memory order violation found; aborting commits and flushing
        auto load = lsq_.getViolatingLoad();
        shouldFlush_ = true;
        flushAfter_ = load->getInstructionId() - 1;
        pc_ = load->getInstructionAddress();

        // Reset sentAtomic if needed
        if (sentAtomic_) sentAtomic_ = false;

        buffer_.pop_front();
        return n + 1;
      }
    }

    // Increment or swap out branch counter for loop detection
    if (uop->isBranch()) {
      if (!loopDetected_) {
        bool increment = true;
        if (branchCounter_.first.address != uop->getInstructionAddress()) {
          // Mismatch on instruction address, reset
          increment = false;
        } else if (branchCounter_.first.outcome != uop->getBranchPrediction()) {
          // Mismatch on branch outcome, reset
          increment = false;
        } else if ((instructionsCommitted_ -
                    branchCounter_.first.commitNumber) > loopBufSize_) {
          // Loop too big to fit in loop buffer, reset
          increment = false;
        }

        if (increment) {
          // Reset commitNumber value
          branchCounter_.first.commitNumber = instructionsCommitted_;
          // Increment counter
          branchCounter_.second++;

          if (branchCounter_.second > loopDetectionThreshold_) {
            // If the same branch with the same outcome is sequentially
            // retired more times than the loopDetectionThreshold_ value,
            // identify as a loop boundary
            loopDetected_ = true;
            sendLoopBoundary_(uop->getInstructionAddress());
          }
        } else {
          // Swap out latest branch
          branchCounter_ = {
              {uop->getInstructionAddress(), uop->getBranchPrediction(),
               instructionsCommitted_},
              0};
        }
      }
    }
    buffer_.pop_front();
    // Reset sentAtomic if needed
    if (sentAtomic_) sentAtomic_ = false;
  }

  return n;
}

void ReorderBuffer::flush(uint64_t afterInsnId) {
  // Iterate backwards from the tail of the queue to find and remove ops newer
  // than `afterInsnId`
  while (!buffer_.empty()) {
    auto& uop = buffer_.back();
    if (uop->getInstructionId() <= afterInsnId) {
      break;
    }

    // To rewind destination registers in correct history order, rewinding of
    // register renaming is done backwards
    auto destinations = uop->getDestinationRegisters();
    for (int i = destinations.size() - 1; i >= 0; i--) {
      const auto& reg = destinations[i];
      rat_.rewind(reg);
    }
    uop->setFlushed();
    // If the instruction is a branch, supply address to branch flushing logic
    if (uop->isBranch()) {
      predictor_.flush(uop->getInstructionAddress());
    }
    buffer_.pop_back();
  }

  // Reset branch counter and loop detection
  branchCounter_ = {{0, {false, 0}, 0}, 0};
  loopDetected_ = false;
}

void ReorderBuffer::flush() {
  buffer_ = std::deque<std::shared_ptr<Instruction>>();
  shouldFlush_ = false;
  // Reset branch counter and loop detection
  branchCounter_ = {{0, {false, 0}, 0}, 0};
  loopDetected_ = false;
}

unsigned int ReorderBuffer::size() const { return buffer_.size(); }

unsigned int ReorderBuffer::getFreeSpace() const {
  return maxSize_ - buffer_.size();
}

bool ReorderBuffer::shouldFlush() const { return shouldFlush_; }
uint64_t ReorderBuffer::getFlushAddress() const { return pc_; }
uint64_t ReorderBuffer::getFlushInsnId() const { return flushAfter_; }

uint64_t ReorderBuffer::getInstructionsCommittedCount() const {
  return instructionsCommitted_;
}

uint64_t ReorderBuffer::getViolatingLoadsCount() const {
  return loadViolations_;
}

void ReorderBuffer::setTid(uint64_t tid) {
  fileOut_.close();
  tid_ = tid;
  std::ostringstream str;
  str << "simeng" << tid_ << ".out";
  fileOut_.open(str.str(), std::ofstream::out | std::ofstream::app);
}

}  // namespace pipeline
}  // namespace simeng
