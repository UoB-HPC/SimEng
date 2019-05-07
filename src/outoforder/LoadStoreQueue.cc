#include "LoadStoreQueue.hh"

#include <cassert>
#include <cstring>

namespace simeng {
namespace outoforder {

/** Check whether requests `a` and `b` overlap. */
bool requestsOverlap(std::pair<uint64_t, uint8_t> a,
                     std::pair<uint64_t, uint8_t> b) {
  // Check whether one region ends before the other begins, implying no overlap,
  // and negate
  return !(a.first + a.second <= b.first || b.first + b.second <= a.first);
}

LoadStoreQueue::LoadStoreQueue(unsigned int maxCombinedSpace, char* memory)
    : maxCombinedSpace(maxCombinedSpace), combined(true), memory(memory){};

LoadStoreQueue::LoadStoreQueue(unsigned int maxLoadQueueSpace,
                               unsigned int maxStoreQueueSpace, char* memory)
    : maxLoadQueueSpace(maxLoadQueueSpace),
      maxStoreQueueSpace(maxStoreQueueSpace),
      combined(false),
      memory(memory){};

unsigned int LoadStoreQueue::getLoadQueueSpace() const {
  if (combined) {
    return getCombinedSpace();
  } else {
    return getLoadQueueSplitSpace();
  }
}
unsigned int LoadStoreQueue::getStoreQueueSpace() const {
  if (combined) {
    return getCombinedSpace();
  } else {
    return getStoreQueueSplitSpace();
  }
}
unsigned int LoadStoreQueue::getTotalSpace() const {
  if (combined) {
    return getCombinedSpace();
  } else {
    return getLoadQueueSplitSpace() + getStoreQueueSplitSpace();
  }
}

unsigned int LoadStoreQueue::getLoadQueueSplitSpace() const {
  return maxLoadQueueSpace - loadQueue.size();
}
unsigned int LoadStoreQueue::getStoreQueueSplitSpace() const {
  return maxStoreQueueSpace - storeQueue.size();
}
unsigned int LoadStoreQueue::getCombinedSpace() const {
  return maxCombinedSpace - loadQueue.size() - storeQueue.size();
}

void LoadStoreQueue::addLoad(const std::shared_ptr<Instruction>& insn) {
  loadQueue.push_back(insn);
}
void LoadStoreQueue::addStore(const std::shared_ptr<Instruction>& insn) {
  storeQueue.push_back(insn);
}

void LoadStoreQueue::startLoad(const std::shared_ptr<Instruction>& insn) {
  // TODO: Defer data read
  const auto& addresses = insn->getGeneratedAddresses();
  for (auto const& request : addresses) {
    const char* address = memory + request.first;
    // Copy the data at the requested memory address into a RegisterValue
    auto data = RegisterValue(address, request.second);

    insn->supplyData(request.first, data);
  }
}

bool LoadStoreQueue::commitStore(std::shared_ptr<Instruction> uop) {
  assert(storeQueue.size() > 0 &&
         "Attempted to commit a store from an empty queue");
  assert(storeQueue.front()->getSequenceId() == uop->getSequenceId() &&
         "Attempted to commit a store that wasn't present at the front of the "
         "store queue");

  const auto& addresses = uop->getGeneratedAddresses();
  const auto& data = uop->getData();
  for (size_t i = 0; i < addresses.size(); i++) {
    const auto& request = addresses[i];

    // Copy data to memory
    const auto& address = memory + request.first;
    memcpy(address, data[i].getAsVector<char>(), request.second);
  }

  for (const auto& load : loadQueue) {
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
            violatingLoad = load;

            storeQueue.pop_front();
            return true;
          }
        }
      }
    }
  }

  storeQueue.pop_front();
  return false;
}

void LoadStoreQueue::commitLoad(std::shared_ptr<Instruction> uop) {
  assert(loadQueue.size() > 0 &&
         "Attempted to commit a load from an empty queue");
  assert(loadQueue.front()->getSequenceId() == uop->getSequenceId() &&
         "Attempted to commit a load that wasn't present at the front of the "
         "load queue");

  loadQueue.pop_front();
}

void LoadStoreQueue::purgeFlushed() {
  auto it = loadQueue.begin();
  while (it != loadQueue.end()) {
    auto& entry = *it;
    if (entry->isFlushed()) {
      it = loadQueue.erase(it);
    } else {
      it++;
    }
  }

  it = storeQueue.begin();
  while (it != storeQueue.end()) {
    auto& entry = *it;
    if (entry->isFlushed()) {
      it = storeQueue.erase(it);
    } else {
      it++;
    }
  }
}

std::shared_ptr<Instruction> LoadStoreQueue::getViolatingLoad() const {
  return violatingLoad;
}

bool LoadStoreQueue::isCombined() const { return combined; }

}  // namespace outoforder
}  // namespace simeng
