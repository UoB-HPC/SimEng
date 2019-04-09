#include "LoadStoreQueue.hh"

#include <cassert>
#include <cstring>

namespace simeng {
namespace pipeline {

/** Check whether requests `a` and `b` overlap. */
bool requestsOverlap(std::pair<uint64_t, uint8_t> a,
                     std::pair<uint64_t, uint8_t> b) {
  // Check whether one region ends before the other begins, implying no overlap,
  // and negate
  return !(a.first + a.second <= b.first || b.first + b.second <= a.first);
}

LoadStoreQueue::LoadStoreQueue(unsigned int maxCombinedSpace, char* memory)
    : maxCombinedSpace_(maxCombinedSpace), combined_(true), memory_(memory){};

LoadStoreQueue::LoadStoreQueue(unsigned int maxLoadQueueSpace,
                               unsigned int maxStoreQueueSpace, char* memory)
    : maxLoadQueueSpace_(maxLoadQueueSpace),
      maxStoreQueueSpace_(maxStoreQueueSpace),
      combined_(false),
      memory_(memory){};

unsigned int LoadStoreQueue::getLoadQueueSpace() const {
  if (combined_) {
    return getCombinedSpace();
  } else {
    return getLoadQueueSplitSpace();
  }
}
unsigned int LoadStoreQueue::getStoreQueueSpace() const {
  if (combined_) {
    return getCombinedSpace();
  } else {
    return getStoreQueueSplitSpace();
  }
}
unsigned int LoadStoreQueue::getTotalSpace() const {
  if (combined_) {
    return getCombinedSpace();
  } else {
    return getLoadQueueSplitSpace() + getStoreQueueSplitSpace();
  }
}

unsigned int LoadStoreQueue::getLoadQueueSplitSpace() const {
  return maxLoadQueueSpace_ - loadQueue_.size();
}
unsigned int LoadStoreQueue::getStoreQueueSplitSpace() const {
  return maxStoreQueueSpace_ - storeQueue_.size();
}
unsigned int LoadStoreQueue::getCombinedSpace() const {
  return maxCombinedSpace_ - loadQueue_.size() - storeQueue_.size();
}

void LoadStoreQueue::addLoad(const std::shared_ptr<Instruction>& insn) {
  loadQueue_.push_back(insn);
}
void LoadStoreQueue::addStore(const std::shared_ptr<Instruction>& insn) {
  storeQueue_.push_back(insn);
}

void LoadStoreQueue::startLoad(const std::shared_ptr<Instruction>& insn) {
  // TODO: Defer data read
  const auto& addresses = insn->getGeneratedAddresses();
  for (auto const& request : addresses) {
    const char* address = memory_ + request.first;
    // Copy the data at the requested memory address into a RegisterValue
    auto data = RegisterValue(address, request.second);

    insn->supplyData(request.first, data);
  }
}

bool LoadStoreQueue::commitStore(const std::shared_ptr<Instruction>& uop) {
  assert(storeQueue_.size() > 0 &&
         "Attempted to commit a store from an empty queue");
  assert(storeQueue_.front()->getSequenceId() == uop->getSequenceId() &&
         "Attempted to commit a store that wasn't present at the front of the "
         "store queue");

  const auto& addresses = uop->getGeneratedAddresses();
  const auto& data = uop->getData();
  for (size_t i = 0; i < addresses.size(); i++) {
    const auto& request = addresses[i];

    // Copy data to memory
    const auto& address = memory_ + request.first;
    memcpy(address, data[i].getAsVector<char>(), request.second);
  }

  for (const auto& load : loadQueue_) {
    // Find all loads ready to commit
    // TODO: Partially ready loads also need disambiguation
    if (load->canCommit()) {
      const auto& loadedAddresses = load->getGeneratedAddresses();
      // Iterate over store addresses
      for (const auto& storeReq : addresses) {
        // Iterate over load addresses
        for (const auto& loadReq : loadedAddresses) {
          // Check for overlapping requests, and flush if discovered
          if (requestsOverlap(storeReq, loadReq)) {
            violatingLoad_ = load;

            storeQueue_.pop_front();
            return true;
          }
        }
      }
    }
  }

  storeQueue_.pop_front();
  return false;
}

void LoadStoreQueue::commitLoad(const std::shared_ptr<Instruction>& uop) {
  assert(loadQueue_.size() > 0 &&
         "Attempted to commit a load from an empty queue");
  assert(loadQueue_.front()->getSequenceId() == uop->getSequenceId() &&
         "Attempted to commit a load that wasn't present at the front of the "
         "load queue");

  loadQueue_.pop_front();
}

void LoadStoreQueue::purgeFlushed() {
  auto it = loadQueue_.begin();
  while (it != loadQueue_.end()) {
    auto& entry = *it;
    if (entry->isFlushed()) {
      it = loadQueue_.erase(it);
    } else {
      it++;
    }
  }

  it = storeQueue_.begin();
  while (it != storeQueue_.end()) {
    auto& entry = *it;
    if (entry->isFlushed()) {
      it = storeQueue_.erase(it);
    } else {
      it++;
    }
  }
}

std::shared_ptr<Instruction> LoadStoreQueue::getViolatingLoad() const {
  return violatingLoad_;
}

bool LoadStoreQueue::isCombined() const { return combined_; }

}  // namespace pipeline
}  // namespace simeng
