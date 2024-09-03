#include "simeng/pipeline/ReorderBuffer.hh"

#include <algorithm>
#include <cassert>
#include <iostream>

namespace simeng {
namespace pipeline {

bool print = true;

ReorderBuffer::ReorderBuffer(
    unsigned int maxSize, RegisterAliasTable& rat, LoadStoreQueue& lsq,
    std::function<void(const std::shared_ptr<Instruction>&)> raiseException,
    std::function<void(uint64_t branchAddress)> sendLoopBoundary,
    std::function<void(const Register& reg)> updateScoreboard,
    BranchPredictor& predictor, uint16_t loopBufSize,
    uint16_t loopDetectionThreshold)
    : rat_(rat),
      lsq_(lsq),
      maxSize_(maxSize),
      raiseException_(raiseException),
      sendLoopBoundary_(sendLoopBoundary),
      updateScoreboard_(updateScoreboard),
      predictor_(predictor),
      loopBufSize_(loopBufSize),
      loopDetectionThreshold_(loopDetectionThreshold) {}

ReorderBuffer::~ReorderBuffer() {
  std::ofstream opcodeFile;
  std::ostringstream opcodeStr;
  opcodeStr << "/Users/jj16791/workspace/opcodes.out";
  opcodeFile.open(opcodeStr.str(), std::ofstream::out);
  opcodeFile.close();
  opcodeFile.open(opcodeStr.str(), std::ofstream::out | std::ofstream::app);
  std::vector<std::pair<std::string, uint64_t>> opcodePairs;
  for (auto& it : opcodesSeen_) {
    opcodePairs.push_back(it);
  }
  std::sort(opcodePairs.begin(), opcodePairs.end(),
            [](auto& a, auto& b) { return a.second > b.second; });
  for (auto& pair : opcodePairs) {
    opcodeFile << pair.first << ": " << pair.second << std::endl;
  }
  opcodeFile.close();

  std::ofstream addrFile;
  std::ostringstream addrStr;
  addrStr << "/Users/jj16791/workspace/addresses.out";
  addrFile.open(addrStr.str(), std::ofstream::out);
  addrFile.close();
  addrFile.open(addrStr.str(), std::ofstream::out | std::ofstream::app);
  std::vector<std::pair<std::string, uint64_t>> addrPairs;
  for (auto& it : addressesSeen_) {
    addrPairs.push_back(it);
  }
  std::sort(addrPairs.begin(), addrPairs.end(),
            [](auto& a, auto& b) { return a.second > b.second; });
  for (auto& pair : addrPairs) {
    addrFile << pair.first << ": " << pair.second << std::endl;
  }
  addrFile.close();

  std::ofstream exeInfoFile;
  std::ostringstream str2;
  str2 << "/Users/jj16791/workspace/exeInfo.out";
  exeInfoFile.open(str2.str(), std::ofstream::out);
  exeInfoFile.close();
  exeInfoFile.open(str2.str(), std::ofstream::out | std::ofstream::app);
  for (auto& vec : executionInfos_) {
    uint64_t idx = 0;
    for (auto& info : vec.second) {
      exeInfoFile << opcodeNames_[vec.first] << "_" << idx++
                  << "\n\tGroup: " << std::get<0>(info)
                  << "\n\tLat: " << std::get<1>(info)
                  << "\n\tStall: " << std::get<2>(info) << "\n\tPorts: {";
      for (auto& pt : std::get<3>(info)) exeInfoFile << portNames_[pt] << " ";
      exeInfoFile << "\b}" << std::endl;
    }
  }
  exeInfoFile.close();
}

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

unsigned int ReorderBuffer::commit(unsigned int maxCommitSize, uint64_t ticks) {
  shouldFlush_ = false;
  size_t maxCommits =
      std::min(static_cast<size_t>(maxCommitSize), buffer_.size());

  unsigned int n = 0;
  for (; n < maxCommits; n++) {
    auto& uop = buffer_.front();

    if (uop->exceptionEncountered()) {
      // outputFile_ << std::hex << uop->getInstructionAddress() << std::dec;
      // outputFile_ << std::endl;
      // lastInsnId_ = uop->getInstructionId();
      // std::cerr << "&:" << uop->getInstructionAddress() << std::endl;
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
      if (waitingOn_.find(uop->getGroup()) == waitingOn_.end())
        waitingOn_[uop->getGroup()] = 1;
      else
        waitingOn_[uop->getGroup()]++;
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
        // uop->setCommitReady(false);
        if (!uop->canCommit()) return n;
      }
    }

    // if (!startCollection_ && uop->getInstructionAddress() == 0x212dd8) {
    //   startCollection_ = true;
    // return 16;
    // std::cerr << "=================" << std::endl;
    // }
    // if (startCollection_ && uop->getInstructionAddress() == 0x212eb4) {
    //   startCollection_ = false;
    // return 17;
    // std::cerr << "=================" << std::endl;
    // }

    if (uop->isLastMicroOp()) {
      instructionsCommitted_++;
    }
    lastAddr_ = uop->getInstructionAddress();
    if (startCollection_) {
      if (executionInfos_.find(uop->getOpcode()) == executionInfos_.end())
        executionInfos_[uop->getOpcode()] = {};
      bool infFound = false;
      for (auto inf : executionInfos_[uop->getOpcode()]) {
        if (std::get<0>(inf) == uop->getGroup() &&
            std::get<1>(inf) == ((uop->isLoad() || uop->isStoreAddress())
                                     ? uop->getLSQLatency()
                                     : uop->getLatency()) &&
            std::get<2>(inf) == uop->getStallCycles())
          infFound = true;
      }
      if (!infFound) {
        executionInfos_[uop->getOpcode()].push_back(
            {uop->getGroup(),
             (uop->isLoad() || uop->isStoreAddress()) ? uop->getLSQLatency()
                                                      : uop->getLatency(),
             uop->getStallCycles(), uop->getSupportedPorts()});
      }

      std::ostringstream opcodeStr;
      opcodeStr << opcodeNames_[uop->getOpcode()] << ":" << uop->getGroup()
                << ":"
                << ((uop->isLoad() || uop->isStoreAddress())
                        ? uop->getLSQLatency()
                        : uop->getLatency())
                << ":" << uop->getStallCycles() << ":{";
      for (const auto& pt : uop->getSupportedPorts())
        opcodeStr << portNames_[pt] << " ";
      opcodeStr << "\b}";
      if (opcodesSeen_.find(opcodeStr.str()) != opcodesSeen_.end()) {
        opcodesSeen_[opcodeStr.str()]++;
      } else {
        opcodesSeen_[opcodeStr.str()] = 1;
      }

      std::ostringstream addrStr;
      addrStr << std::hex << uop->getInstructionAddress() << std::dec << ":"
              << opcodeNames_[uop->getOpcode()] << ":" << uop->getGroup() << ":"
              << ((uop->isLoad() || uop->isStoreAddress())
                      ? uop->getLSQLatency()
                      : uop->getLatency())
              << ":" << uop->getStallCycles() << ":{";
      for (const auto& pt : uop->getSupportedPorts())
        addrStr << portNames_[pt] << " ";
      addrStr << "\b}";
      if (addressesSeen_.find(addrStr.str()) != addressesSeen_.end()) {
        addressesSeen_[addrStr.str()]++;
      } else {
        addressesSeen_[addrStr.str()] = 1;
      }
    }

    const auto& destinations = uop->getDestinationRegisters();
    const auto& results = uop->getResults();
    // if (startCollection_) {
    if (print) {
      if (lastInsnId_ != uop->getInstructionId()) {
        outputFile_ << std::hex << uop->getInstructionAddress() << std::dec;
        // outputFile_ << " (" << uop->getOpcode() << ")";
        // outputFile_ << " (" << uop->getSequenceId() << ")";
        outputFile_ << std::endl;

        outputFile2_ << std::hex << uop->getInstructionAddress() << std::dec;
        // outputFile2_ << " (" << uop->getOpcode() << ")";
        outputFile2_ << " (" << uop->getSequenceId() << ")";
        outputFile2_ << std::endl;
      }

      if (uop->isLoad()) {
        const auto& addrs = uop->getGeneratedAddresses();
        for (int i = 0; i < addrs.size(); i++) {
          outputFile_ << "\tAddr " << std::hex << addrs[i].vaddr << std::dec
                      << std::endl;
          outputFile2_ << "\tAddr " << std::hex << addrs[i].vaddr << std::dec
                       << std::endl;
        }
      }
      if (uop->isStoreAddress()) {
        const auto& addrs = uop->getGeneratedAddresses();

        for (int i = 0; i < addrs.size(); i++) {
          outputFile_ << "\tAddr " << std::hex << addrs[i].vaddr << std::dec
                      << " <- " << std::hex;
          outputFile2_ << "\tAddr " << std::hex << addrs[i].vaddr << std::dec
                       << " <- " << std::hex;
          if (uop->isStoreData()) {
            const auto& data = uop->getData();
            for (int j = data[i].size() - 1; j >= 0; j--) {
              if (data[i].getAsVector<uint8_t>()[j] < 16) {
                outputFile_ << "0";
                outputFile2_ << "0";
              }
              outputFile_ << unsigned(data[i].getAsVector<uint8_t>()[j]);
              outputFile2_ << unsigned(data[i].getAsVector<uint8_t>()[j]);
            }
            outputFile_ << std::dec << std::endl;
            outputFile2_ << std::dec << std::endl;
          }
        }
      } else if (uop->isStoreData()) {
        const auto& data = uop->getData();
        for (int i = 0; i < data.size(); i++) {
          for (int j = data[i].size() - 1; j >= 0; j--) {
            if (data[i].getAsVector<uint8_t>()[j] < 16) {
              outputFile_ << "0";
              outputFile2_ << "0";
            }
            outputFile_ << unsigned(data[i].getAsVector<uint8_t>()[j]);
            outputFile2_ << unsigned(data[i].getAsVector<uint8_t>()[j]);
          }
        }
        outputFile_ << std::dec << std::endl;
        outputFile2_ << std::dec << std::endl;
      }
      for (int i = 0; i < destinations.size(); i++) {
        outputFile_ << "\t{" << unsigned(destinations[i].type) << ":"
                    << rat_.reverseMapping(destinations[i]).tag << "}"
                    << " <- " << std::hex;
        outputFile2_ << "\t{" << unsigned(destinations[i].type) << ":"
                     << rat_.reverseMapping(destinations[i]).tag << "}"
                     << " <- " << std::hex;
        for (int j = results[i].size() - 1; j >= 0; j--) {
          if (results[i].getAsVector<uint8_t>()[j] < 16) {
            outputFile_ << "0";
            outputFile2_ << "0";
          }
          outputFile_ << unsigned(results[i].getAsVector<uint8_t>()[j]);
          outputFile2_ << unsigned(results[i].getAsVector<uint8_t>()[j]);
        }
        outputFile_ << std::dec << std::endl;
        outputFile2_ << std::dec << std::endl;
      }

      lastInsnId_ = uop->getInstructionId();
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
    // if (uop->isBranch()) {
    //   if (!loopDetected_) {
    //     bool increment = true;
    //     if (branchCounter_.first.address != uop->getInstructionAddress()) {
    //       // Mismatch on instruction address, reset
    //       increment = false;
    //     } else if (branchCounter_.first.outcome !=
    //     uop->getBranchPrediction()) {
    //       // Mismatch on branch outcome, reset
    //       increment = false;
    //     } else if ((instructionsCommitted_ -
    //                 branchCounter_.first.commitNumber) > loopBufSize_) {
    //       // Loop too big to fit in loop buffer, reset
    //       increment = false;
    //     }

    //     if (increment) {
    //       // Reset commitNumber value
    //       branchCounter_.first.commitNumber = instructionsCommitted_;
    //       // Increment counter
    //       branchCounter_.second++;

    //       if (branchCounter_.second > loopDetectionThreshold_) {
    //         // If the same branch with the same outcome is sequentially
    //         // retired more times than the loopDetectionThreshold_ value,
    //         // identify as a loop boundary
    //         loopDetected_ = true;
    //         sendLoopBoundary_(uop->getInstructionAddress());
    //       }
    //     } else {
    //       // Swap out latest branch
    //       branchCounter_ = {
    //           {uop->getInstructionAddress(), uop->getBranchPrediction(),
    //            instructionsCommitted_},
    //           0};
    //     }
    //   }
    // }

    // If it is a branch, now update the predictor (here to ensure order of
    // updates is correct)
    if (uop->isBranch()) {
      predictor_.update(uop->getInstructionAddress(), uop->wasBranchTaken(),
                        uop->getBranchAddress(), uop->getBranchType(),
                        uop->getInstructionId());
      // Update the branches retired and mispredicted counters
      retiredBranches_++;
      if (uop->wasBranchMispredicted()) branchMispredicts_++;
    }

    if (uop->isSequential()) {
      buffer_.pop_front();
      // Reset sentAtomic if needed
      if (sentAtomic_) sentAtomic_ = false;
      return n + 1;
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

    // Check whether the instruction has dispatched, but has not yet written
    // back
    bool hasScoreboardEntries =
        uop->hasDispatched() && !(uop->isWaitingCommit() || uop->canCommit());

    // To rewind destination registers in correct history order, rewinding of
    // register renaming is done backwards
    auto destinations = uop->getDestinationRegisters();
    for (int i = destinations.size() - 1; i >= 0; i--) {
      const auto& reg = destinations[i];
      rat_.rewind(reg);
      // If needed, clear scoreboard entry for destination register
      if (hasScoreboardEntries) updateScoreboard_(reg);
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

uint64_t ReorderBuffer::getBranchMispredictedCount() const {
  return branchMispredicts_;
}

uint64_t ReorderBuffer::getRetiredBranchesCount() const {
  return retiredBranches_;
}

void ReorderBuffer::setTid(uint64_t tid) {
  tid_ = tid;
  if (print) {
    outputFile_.close();
    std::ostringstream str;
    str << "/home/br-jjones/simulation/multithread" << tid_ << "Retire.out";
    outputFile_.open(str.str(), std::ofstream::out | std::ofstream::app);

    outputFile2_.close();
    std::ostringstream str2;
    str2 << "/home/br-jjones/simulation/multithread" << tid_
         << "RetireWithIDs.out";
    outputFile2_.open(str2.str(), std::ofstream::out | std::ofstream::app);
  }
}

}  // namespace pipeline
}  // namespace simeng
