#pragma once

#include <stdint.h>
#include <sys/mman.h>

#include <cstddef>
#include <iostream>
#include <memory>
#include <vector>

#include "simeng/util/Math.hh"

namespace simeng {
namespace OS {

class HostBackedFileMMaps;
class HostFileMMap;
class Vmall;

enum VMAType { Stack, Heap, PTLoad, Mmap };
/** class representing vm_area_struct in linux. (Linked List) */
class VirtualMemoryArea {
 private:
  /** Protection specified by the mmap call. */
  int prot_ = -1;
  /** Flags specified by the mmap call. */
  int flags_ = -1;

  void* filebuf_ = nullptr;
  size_t fsize_ = 0;
  HostFileMMap* hfmmap_ = nullptr;

 public:
  /** The address representing the end of the memory allocation. */
  uint64_t vm_end = 0;
  /** The address representing the start of the memory allocation. */
  uint64_t vm_start = 0;
  /** The next allocation in the contiguous list. */
  VirtualMemoryArea* vm_next = NULL;
  /** The size of the virtual memory area. */
  size_t size = 0;

  VMAType type_;

  VirtualMemoryArea(int prot, int flags, size_t vsize, VMAType type,
                    HostFileMMap* hfmmap = nullptr);
  VirtualMemoryArea(VirtualMemoryArea* vma);
  ~VirtualMemoryArea();

  bool hasFile();

  bool overlaps(uint64_t startAddr, size_t size);
  bool contains(uint64_t startAddr, size_t size);
  bool contains(uint64_t startAddr);
  bool containedIn(uint64_t startAddr, size_t size);
  void trimRangeStart(uint64_t addr);
  void trimRangeEnd(uint64_t addr);
  void* getFileBuf();
  size_t getFileSize();
};

class HostFileMMap {
 public:
  const int fd_;
  const size_t flen_;
  const off_t offset_;
  HostFileMMap(int fd, void* faddr, size_t flen, off_t offset)
      : fd_(fd), faddr_(faddr), flen_(flen), offset_(offset) {}
  void* getfaddr() { return faddr_; }

 private:
  void* faddr_;
};

class HostBackedFileMMaps {
 private:
  std::vector<HostFileMMap*> hostvec;

 public:
  ~HostBackedFileMMaps();
  HostFileMMap* mapfd(int fd, size_t len, off_t offset);
};

typedef VirtualMemoryArea VMA;

}  // namespace OS
}  // namespace simeng
