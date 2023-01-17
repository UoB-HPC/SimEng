#include "simeng/kernel/PageFrameAllocator.hh"

#include <iostream>

#include "simeng/util/Math.hh"
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
    entry = new AllocEntry();
    entry->track = 0;
    entry->startAddr_ = alloccnt * pageSize_ * 64;
    entry->nextFreeAddr = entry->startAddr_;
    entry->size_ = 0;
    entries_[alloccnt] = entry;
  }

  uint64_t track = entry->track;
  track = populateFrameTrack(track, size);

  uint64_t phyAddr =
      entry->size_ == 0 ? entry->startAddr_ : entry->nextFreeAddr;
  entry->track = track;
  entry->size_ += size;
  entry->nextFreeAddr += size;
  return phyAddr;
};

uint64_t PageFrameAllocator::allocate(size_t size) {
  uint64_t startAddr = 0;
  size = roundUpMemAddr(size, pageSize_);

  while (size > maxAllocEntrySize) {
    uint64_t addr = allocatePageFrames(maxAllocEntrySize);
    if (startAddr == 0) {
      startAddr = addr;
    };
    size -= maxAllocEntrySize;
  }

  if (size <= 0) return startAddr;
  uint64_t addr = allocatePageFrames(size);
  if (startAddr == 0) {
    startAddr = addr;
  };

  return startAddr;
};

uint64_t PageFrameAllocator::populateFrameTrack(uint64_t track, size_t size) {
  uint8_t numOnes = size / pageSize_;
  size_t count;
  uint64_t tc = track;
  for (count = 0; count < 64; count++) {
    uint64_t bit = tc & 1;
    tc >>= 1;
    if (bit) break;
  }
  uint64_t shiftCnt = count - numOnes;
  uint64_t overlapValue = ~(0);
  overlapValue >>= (64 - numOnes);
  overlapValue <<= shiftCnt;
  track |= overlapValue;
  return track;
}

}  // namespace kernel
}  // namespace simeng
