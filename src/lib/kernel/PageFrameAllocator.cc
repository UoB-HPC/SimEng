#include "simeng/kernel/PageFrameAllocator.hh"

namespace simeng {
namespace kernel {

PageFrameAllocator::PageFrameAllocator() { entries_.fill(NULL); };

PageFrameAllocator::~PageFrameAllocator() {
  for (auto entry : entries_) {
    if (entry != NULL) delete entry;
  }
};

uint64_t PageFrameAllocator::allocatePageFrames(size_t size) {
  AllocEntry* entry = NULL;
  size_t alloccnt;
  // Loop through entires and find allocation entry with free size;
  for (alloccnt = 0; alloccnt < 16; alloccnt++) {
    entry = entries_[alloccnt];
    if (entry == NULL) break;
    if (entry->track != ULLONG_MAX && maxAllocEntrySize - entry->size_ > size)
      break;
  }

  // if entry is null we need to create a new allocation entry;
  if (entry == NULL) {
    entry = new AllocEntry{0, alloccnt * pageSize_, alloccnt * pageSize_, 0};
    entries_[alloccnt] = entry;
  }

  uint8_t bitcnt = 0;
  uint64_t track = entry->track;
  if (track == 0) {
    track = 1;
    track <<= 63;
    bitcnt = 0;
  } else {
    for (bitcnt = 0; bitcnt < 64; bitcnt++) {
      uint8_t bit = track & 1;
      track >>= 1;
      if (bit) break;
    }
    track |= (1 << bitcnt);
  }

  uint64_t phyAddr = entry->nextFreeAddr;
  entry->track = track;
  entry->size_ += size;
  entry->nextFreeAddr += size;
  return phyAddr;
};

uint64_t PageFrameAllocator::allocate(size_t size) {
  uint64_t startAddr = 0;
  while (size > maxAllocEntrySize) {
    uint64_t addr = allocatePageFrames(maxAllocEntrySize);
    if (!startAddr) startAddr = addr;
    size -= maxAllocEntrySize;
  }
  if (size <= 0) return startAddr;

  uint16_t addr = allocatePageFrames(size);
  if (!startAddr) startAddr = addr;

  return startAddr;
};

}  // namespace kernel
}  // namespace simeng
