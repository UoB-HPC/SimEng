#include "LoadStoreQueue.hh"

#include <cassert>
#include <cstring>

namespace simeng {
namespace outoforder {

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
    // Copy the data at the requested memory address into a RegisterValue
    auto data = RegisterValue(memory + request.first, request.second);

    insn->supplyData(request.first, data);
  }
}

void LoadStoreQueue::commitStore() {
  assert(storeQueue.size() > 0 &&
         "Attempted to commit a store from an empty queue");

  const auto& uop = storeQueue.front();
  auto addresses = uop->getGeneratedAddresses();
  auto data = uop->getData();
  for (size_t i = 0; i < addresses.size(); i++) {
    auto request = addresses[i];

    // Copy data to memory
    auto address = memory + request.first;
    memcpy(address, data[i].getAsVector<char>(), request.second);
  }

  // TODO: Search load queue for memory order violations and flush if discovered

  storeQueue.pop_front();
}

void LoadStoreQueue::commitLoad() {
  assert(loadQueue.size() > 0 &&
         "Attempted to commit a load from an empty queue");

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

  while (it != storeQueue.end()) {
    auto& entry = *it;
    if (entry->isFlushed()) {
      it = storeQueue.erase(it);
    } else {
      it++;
    }
  }
}

}  // namespace outoforder
}  // namespace simeng
