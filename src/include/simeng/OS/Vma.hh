#pragma once

#include <stdint.h>
#include <sys/mman.h>

#include <cstddef>
#include <functional>
#include <iostream>
#include <memory>
#include <utility>
#include <vector>

#include "simeng/OS/Constants.hh"
#include "simeng/util/Math.hh"

namespace simeng {
namespace OS {

using namespace simeng::OS::defaults;

/** A HostFileMMap is a structure representing a file mmaped on the host. */
class HostFileMMap {
 public:
  /** Default constructor for HostFileMMap. */
  HostFileMMap() {}

  /** Constructor used to construct HostFileMMap with the specific values. */
  HostFileMMap(int fd, void* origPtr, void* faddr, size_t origLen, size_t flen,
               off_t offset)
      : fd_(fd),
        origLen_(origLen),
        flen_(flen),
        offset_(offset),
        origPtr_(origPtr),
        faddr_(faddr),
        isEmpty_(false) {}

  /** Default move constructor for HostFileMMap to enable copy elision whenever
   * possible. */
  HostFileMMap(HostFileMMap&& hfmmap) = default;

  /** Default copy constructor for HostFileMMap. */
  HostFileMMap(const HostFileMMap& hfmmap) = default;

  /** Default copy assignment operator for HostFileMMap. */
  HostFileMMap& operator=(const HostFileMMap& hfmmap) = default;

  /** Default move assignment operator for the HostFileMMap to enable copy
   * elision whenever possible. */
  HostFileMMap& operator=(HostFileMMap&& hfmmap) = default;

  /** Method which returns the pointer of the mmaped file. */
  void* getFaddr() { return faddr_; }

  /** Method which returns the original starting pointer to the mmaped file.*/
  void* getOrigPtr() { return origPtr_; }

  /** Returns the fd assosciated with HostFileMMap. */
  int getFd() { return fd_; }

  /** Returns the offset assosciated with HostFileMMap. */
  int getOffset() { return offset_; }

  /** Returns the effective length of the of faddr_. */
  int getLen() { return flen_; }

  /** Returns the length of origPtr_. */
  int getOrigLen() { return origLen_; }

  /** Method which return if HostFileMMap is empty or not. */
  bool isEmpty() { return isEmpty_; }

 private:
  /** Host fd of the file mmaped by host. */
  int fd_ = 0;

  /** This is the size of the original file mapping without the offset being
   * applied to it. */
  size_t origLen_ = 0;

  /** Length of the file mapping after offset has been applied. When a mmap call
  is made, it can contain an offset which has to be a multiple of page size.
  Whenever a mmap call is made with a file descriptor and offset, SimEng mmaps
  the entire file on the host system. The effective length given the original
  file length and offset is then calculated i.e original_file_length - offset.
  This ensures SimEng doesn't run into alignment conflicts due to different page
  sizes on different systems. */
  size_t flen_ = 0;

  /** This is the offset specified by the mmap syscall. */
  off_t offset_ = 0;

  /** The starting pointer assosciated with the file mapping. When using host
   * mmap SimEng doesn't specify any offsets to avoid page size alignment
   * conflicts, instead it mmaps the entire file and calculates offsetted values
   * used during the simulation. */
  void* origPtr_ = nullptr;

  /** This is the effective starting pointer used during simulation. It is
   * calculated by doing simple pointer arithmetic i.e faddr_ = (origPtr_ +
   * offset_). */
  void* faddr_ = nullptr;

  /** Boolean used to check if the HostFileMMap is empty or not. */
  bool isEmpty_ = true;
};

/** The HostBackedFileMMaps allows us to mmap a host file descriptor so that the
 * mapping can be used in SimEng's VMAs. The HostBackedFileMMaps class is
 * responsible for managing these mmaped files, hence once the class is
 * destroyed, it also unmaps every mapping on the host. */
class HostBackedFileMMaps {
 public:
  HostBackedFileMMaps() {}

  ~HostBackedFileMMaps();

  /** Method used to a mmap a host fd. */
  HostFileMMap mapfd(int fd, size_t len, off_t offset);

 private:
  /** Vector of all host file mappings. */
  std::vector<HostFileMMap> hostVec_;
};

/** Typedef for callback function used to mmap a file onto the host through the
 * HostBackedFileMMaps::mapfd function. */
typedef std::function<HostFileMMap(int, size_t, off_t)> mmapFileOnHost;

/** class representing a vm_area_struct in linux. Each Virtual Memory Area (VMA)
 * describes a range of virtual addresses that are mapped to memory. A VMA can
 * also have a file assosciated with it; accessing an address from such a VMA
 * allows us to access the file's contents. The address range in a VMA is
 * exclusive of its end address i.e [vmStart_, vmEnd_). */
class VirtualMemoryArea {
 public:
  /* Constructor which constructs the VirtualMemoryArea with specific values.*/
  VirtualMemoryArea(int prot, int flags, size_t vsize, HostFileMMap hfmmap);

  /* Constructor which copies the contents of a VMA pointer into the the current
   * VMA. This method is used in MemRegion::removeVMA to create a copy of the
   * VMA so that it can be split into two. */
  VirtualMemoryArea(VirtualMemoryArea* vma);

  ~VirtualMemoryArea(){};

  /** The address representing the end of the memory allocation. */
  uint64_t vmEnd_ = 0;

  /** The address representing the start of the memory allocation. */
  uint64_t vmStart_ = 0;

  /** The next allocation in the contiguous list. */
  VirtualMemoryArea* vmNext_ = nullptr;

  /** The size of the virtual memory area. */
  size_t vmSize_ = 0;

  /** Method to check if the VMA has a file.  */
  bool hasFile();

  /** Method to check if the VMA overlaps with addr range. */
  bool overlaps(uint64_t startAddr, size_t size);

  /** Method to check if the VMA contains addr range. */
  bool contains(uint64_t startAddr, size_t size);

  /** Method to check if the VMA contains addr. */
  bool contains(uint64_t startAddr);

  /** Method to check if the VMA is contained inside an addr range. */
  bool containedIn(uint64_t startAddr, size_t size);

  /** Method which trims the VMA from vmStart_ to addr. */
  void trimRangeStart(uint64_t addr);

  /** Method which trims the VMA from addr to vmEnd_. */
  void trimRangeEnd(uint64_t addr);

  /** Method which returns filebuf assosciated with the VMA. */
  void* getFileBuf();

  /** Method which returns file size of filebuf. */
  size_t getFileSize();

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
  HostFileMMap hfmmap_;
};

typedef VirtualMemoryArea VMA;

}  // namespace OS
}  // namespace simeng
