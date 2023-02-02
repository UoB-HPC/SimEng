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

/**
 * class representing vm_area_struct in linux. Each VMA describes a range of
 * virtual address that are mapped to memory. VMA can have file assosciated with
 * them, hence accessing an address from a VMA containing a file allows us
 * access the file's content. The address range in a VMA is exclusive of its end
 * address i.e [vmStart_, vmEnd_)
 * */
class VirtualMemoryArea {
 private:
  /** Protection specified by the mmap call. */
  int prot_ = -1;
  /** Flags specified by the mmap call. */
  int flags_ = -1;
  /** File buffer which holds the pointer to host mapped file. */
  void* filebuf_ = nullptr;
  /** Size of the file in bytes. */
  size_t fsize_ = 0;
  /** Reference to the HostFileMMap associated with this VMA. */
  HostFileMMap* hfmmap_ = nullptr;

 public:
  /** The address representing the end of the memory allocation. */
  uint64_t vmEnd_ = 0;
  /** The address representing the start of the memory allocation. */
  uint64_t vmStart_ = 0;
  /** The next allocation in the contiguous list. */
  VirtualMemoryArea* vmNext_ = NULL;
  /** The size of the virtual memory area. */
  size_t vmSize_ = 0;

  VirtualMemoryArea(int prot, int flags, size_t vsize,
                    HostFileMMap* hfmmap = nullptr);
  VirtualMemoryArea(VirtualMemoryArea* vma);
  ~VirtualMemoryArea();
  /** Method to check if VMA has a file.  */
  bool hasFile();

  /** Method to check if VMA overlaps with addr range. */
  bool overlaps(uint64_t startAddr, size_t size);

  /** Method to check if VMA contains addr range. */
  bool contains(uint64_t startAddr, size_t size);

  /** Method to check if VMA contains addr. */
  bool contains(uint64_t startAddr);

  /** Method to check if VMA is contained inside an addr range. */
  bool containedIn(uint64_t startAddr, size_t size);

  /** Method which trims the VMA from vmStart_ to addr. */
  void trimRangeStart(uint64_t addr);

  /** Method which trims the VMA from addr to vmEnd_. */
  void trimRangeEnd(uint64_t addr);

  /** Method which returns filebuf assosciated with the VMA. */
  void* getFileBuf();

  /** Method which returns file size of filebuf. */
  size_t getFileSize();
};

/** A HostFileMMap is structure represent a file mmaped on the host. */
class HostFileMMap {
 public:
  /** Host fd of the file mmaped by host. */
  const int fd_;
  /** length of the file mapping. */
  const size_t flen_;
  /** offset of the mapping. */
  const off_t offset_;

  const size_t origLen_;

  HostFileMMap(int fd, void* origPtr, void* faddr, size_t origLen, size_t flen,
               off_t offset)
      : fd_(fd),
        origPtr_(origPtr),
        faddr_(faddr),
        origLen_(origLen),
        flen_(flen),
        offset_(offset) {}

  /** Method which returns the pointer of the mmaped file. */
  void* getfaddr() { return faddr_; }

  void* getOrigPtr() { return origPtr_; }

 private:
  /** Pointer assosciated with the file mapping. */
  void* faddr_;

  void* origPtr_;
};

/**
 * The HostBackedFileMMaps allows us to mmap a host file description use to the
 * mapping in SimEng's VMAs. The HostBackedFileMMaps class is responsible to
 * managing these mmaped files, hence once the class is destroyed it also unmaps
 * every mapping.
 */
class HostBackedFileMMaps {
 private:
  /** Vector of all host file maps. */
  std::vector<HostFileMMap*> hostvec;

 public:
  ~HostBackedFileMMaps();
  /** Method used to a mmap a host fd. */
  HostFileMMap* mapfd(int fd, size_t len, off_t offset);
};

typedef VirtualMemoryArea VMA;

}  // namespace OS
}  // namespace simeng
