#include "simeng/OS/Vma.hh"

#include <sys/stat.h>

#include <cstddef>

namespace simeng {
namespace OS {
HostFileMMap HostBackedFileMMaps::mapfd(int fd, size_t len, off_t offset) {
  if (offset & (PAGE_SIZE - 1)) {
    std::cerr << "[SimEng:HostBackedFileMMaps] Failed to create Host backed "
                 "file mapping. Offset is not aligned "
                 "to page size: "
              << offset << std::endl;
    std::exit(1);
  }
  struct stat* statbuf = (struct stat*)malloc(sizeof(struct stat));
  int fstatResult = fstat(fd, statbuf);
  if (fstatResult < 0) {
    std::cerr << "[SimEng:HostBackedFileMMaps] fstat failed: Cannot create "
                 "host backed file mmap for file "
                 "descriptor - "
              << fd << std::endl;
    free(statbuf);
    std::exit(1);
  }
  off_t fstatFileSize = statbuf->st_size;
  free(statbuf);
  if (offset + len > fstatFileSize) {
    std::cerr << "[SimEng:HostBackedFileMMaps] Tried to create host backed "
                 "file mmap with offset and size greater "
                 "than file size."
              << std::endl;
    std::exit(1);
  }
  if (len <= 0) {
    std::cerr << "[SimEng:HostBackedFileMMaps] Cannot create host backed file "
                 "mmap with size 0 for file "
                 "descriptor: "
              << fd << std::endl;
    std::exit(1);
  }
  // Always pass offset 0 as it must be aligned to host page size, which can
  // differ (i.e. MacOS has page size of 16KiB).
  void* filemmap = mmap(NULL, (size_t)statbuf->st_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE, fd, 0);
  // Add offset to pointer manually
  char* offsettedPtr = (char*)filemmap + offset;
  void* newPtr = (void*)offsettedPtr;
  HostFileMMap hfmm =
      HostFileMMap(fd, filemmap, newPtr, (size_t)statbuf->st_size, len, offset);
  hostVec_.push_back(hfmm);
  return hfmm;
}

HostBackedFileMMaps::~HostBackedFileMMaps() {
  for (auto fmap : hostVec_) {
    // Since HostFileMMap contains effective starting address and file length
    // values calculated after applying the offset specified by mmap. We have to
    // be cautious and use origPtr_ and orgiLen_ here to unmap the entire file
    // mapping on host.
    if (munmap(fmap.getOrigPtr(), fmap.getOrigLen()) < 0) {
      std::cerr << "[SimEng:HostBackedFileMMaps] Unable to unmap host backed "
                   "file mmap associated with file "
                   "descriptor: "
                << fmap.getFd() << std::endl;
      std::exit(1);
    }
  }
}

VirtualMemoryArea::VirtualMemoryArea(int prot, int flags, size_t vsize,
                                     HostFileMMap hfmmap) {
  vmSize_ = vsize;
  prot_ = prot;
  flags_ = flags;
  hfmmap_ = hfmmap;
  if (!hfmmap.isEmpty()) {
    filebuf_ = hfmmap.getFaddr();
    fsize_ = hfmmap.getLen();
  }
}

VirtualMemoryArea::VirtualMemoryArea(VirtualMemoryArea* vma)
    : vmEnd_(vma->vmEnd_),
      vmStart_(vma->vmStart_),
      vmNext_(vma->vmNext_),
      vmSize_(vma->vmSize_),
      prot_(vma->prot_),
      flags_(vma->flags_),
      filebuf_(vma->filebuf_),
      fsize_(vma->fsize_),
      hfmmap_(vma->hfmmap_) {}

bool VirtualMemoryArea::overlaps(uint64_t startAddr, size_t size) {
  uint64_t endAddr = startAddr + size;
  return (endAddr >= vmStart_) && (startAddr < vmEnd_);
}

bool VirtualMemoryArea::contains(uint64_t startAddr, size_t size) {
  uint64_t endAddr = startAddr + size;
  return (startAddr >= vmStart_) && (endAddr <= vmEnd_);
}

bool VirtualMemoryArea::contains(uint64_t vaddr) {
  return (vaddr >= vmStart_) && (vaddr < vmEnd_);
}

bool VirtualMemoryArea::containedIn(uint64_t startAddr, size_t size) {
  uint64_t endAddr = startAddr + size;
  return (startAddr <= vmStart_) && (endAddr >= vmEnd_);
}

void VirtualMemoryArea::trimRangeEnd(uint64_t addr) {
  vmSize_ = addr - vmStart_;
  vmEnd_ = addr;
  // We dont host munmap here because the class HostBackedFileMMaps is
  // responsible for managing all host mappings. We only update the file size to
  // the new size only if it is less than the original size before trim.
  if (hasFile()) fsize_ = (fsize_ < vmSize_) ? fsize_ : vmSize_;
}

void VirtualMemoryArea::trimRangeStart(uint64_t addr) {
  if (hasFile()) {
    size_t trimlen = addr - vmStart_;
    if (trimlen >= fsize_) {
      // We dont munmap filebuf_ here because the HostBackedFileMMaps class is
      // responsible for managing all file mappings. If trimLen is greater than
      // fsize_ just update the filebuf_ and fsize_ variables to signify that no
      // file exists.
      filebuf_ = nullptr;
      fsize_ = 0;
    } else {
      // If entire file size is not trimmed, update the filebuf pointer with an
      // offset. Since the start address of the VMA has been changed, the new
      // start address should point to an offsetted position in the file.
      char* ptr = (char*)filebuf_ + trimlen;
      filebuf_ = (void*)ptr;
      fsize_ -= trimlen;
    }
  }
  vmSize_ = vmEnd_ - addr;
  vmStart_ = addr;
}

bool VirtualMemoryArea::hasFile() { return filebuf_ != nullptr && fsize_ != 0; }

void* VirtualMemoryArea::getFileBuf() { return filebuf_; }

size_t VirtualMemoryArea::getFileSize() { return fsize_; }

}  // namespace OS
}  // namespace simeng
