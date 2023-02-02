#include "simeng/kernel/Vma.hh"

#include <sys/stat.h>

#include <cstddef>

namespace simeng {
namespace kernel {

HostFileMMap* HostBackedFileMMaps::mapfd(int fd, size_t len, off_t offset) {
  struct stat* statbuf = (struct stat*)malloc(sizeof(struct stat));
  if (offset & (4096 - 1)) {
    std::cerr
        << "Failed to create Host backed file mapping. Offset is not aligned "
           "to page size: "
        << offset << std::endl;
    std::exit(1);
  }
  if (fstat(fd, statbuf) < 0) {
    std::cerr << "fstat failed: Cannot create host backed file mmap for file "
                 "descriptor - "
              << fd << std::endl;
    std::exit(1);
  };
  if (offset + len > statbuf->st_size) {
    std::cerr
        << "Tried to create host backed file mmap with offset and size greater "
           "than file size."
        << std::endl;
    std::exit(1);
  }
  if (len == 0) {
    std::cerr << "Cannot create host backed file mmap with size 0 for file "
                 "descriptor: "
              << fd << std::endl;
    std::exit(1);
  }
  void* filemmap =
      mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, offset);
  HostFileMMap* hfmm = new HostFileMMap(fd, filemmap, len, offset);
  hostvec.push_back(hfmm);
  return hfmm;
};

HostBackedFileMMaps::~HostBackedFileMMaps() {
  for (auto fmap : hostvec) {
    if (munmap(fmap->getfaddr(), fmap->flen_) < 0) {
      std::cerr << "Unable to unmap host backed file mmap associated with file "
                   "descriptor: "
                << fmap->fd_ << std::endl;
      std::exit(1);
    }
    delete fmap;
  }
};

VirtualMemoryArea::VirtualMemoryArea(int prot, int flags, size_t vsize,
                                     HostFileMMap* hfmmap) {
  vmSize_ = vsize;
  prot_ = prot;
  flags_ = flags;
  hfmmap_ = hfmmap;
  if (hfmmap != nullptr) {
    filebuf_ = hfmmap->getfaddr();
    fsize_ = hfmmap->flen_;
  }
};

VirtualMemoryArea::VirtualMemoryArea(VirtualMemoryArea* vma) {
  vmStart_ = vma->vmStart_;
  vmEnd_ = vma->vmEnd_;
  vmNext_ = vma->vmNext_;
  flags_ = vma->flags_;
  prot_ = vma->prot_;
  hfmmap_ = vma->hfmmap_;
  vmSize_ = vma->vmSize_;
  filebuf_ = vma->filebuf_;
  fsize_ = vma->fsize_;
};

VirtualMemoryArea::~VirtualMemoryArea(){};

bool VirtualMemoryArea::overlaps(uint64_t startAddr, size_t size) {
  uint64_t endAddr = startAddr + size;
  return (endAddr >= vmStart_) && (startAddr < vmEnd_);
};

bool VirtualMemoryArea::contains(uint64_t startAddr, size_t size) {
  uint64_t endAddr = startAddr + size;
  return (startAddr >= vmStart_) && (endAddr <= vmEnd_);
};

bool VirtualMemoryArea::contains(uint64_t vaddr) {
  return (vaddr >= vmStart_) && (vaddr < vmEnd_);
}

bool VirtualMemoryArea::containedIn(uint64_t startAddr, size_t size) {
  uint64_t endAddr = startAddr + size;
  return (startAddr <= vmStart_) && (endAddr >= vmEnd_);
};

void VirtualMemoryArea::trimRangeEnd(uint64_t addr) {
  vmSize_ = addr - vmStart_;
  vmEnd_ = addr;
  // We dont host munmap here because HostBackedFileMMaps is responsible for
  // managing all host mappings. We only update the file size to the new size
  // only if it is less than the original size before trim.
  if (hasFile()) fsize_ = fsize_ < vmSize_ ? fsize_ : vmSize_;
};

void VirtualMemoryArea::trimRangeStart(uint64_t addr) {
  if (hasFile()) {
    size_t trimlen = addr - vmStart_;
    if (trimlen >= fsize_) {
      // We dont host munmap here because HostBackedFileMMaps is responsible for
      // managing all host mappings. If the entire file size is trimmed just
      // update the filebuf_ and fsize_ variables.
      filebuf_ = NULL;
      fsize_ = 0;
    } else {
      // If entire file size is not trimmed, update the filebuf pointer with an
      // offset. Since the start address of the VMA has been changed, the new
      // start address should point to an offseted position in the file.
      char* ptr = (char*)filebuf_ + trimlen;
      filebuf_ = (void*)ptr;
      fsize_ -= trimlen;
    }
  }
  vmSize_ = vmEnd_ - addr;
  vmStart_ = addr;
};

bool VirtualMemoryArea::hasFile() {
  return filebuf_ != nullptr && fsize_ != 0;
};

void* VirtualMemoryArea::getFileBuf() { return filebuf_; }

size_t VirtualMemoryArea::getFileSize() { return fsize_; }

}  // namespace kernel
}  // namespace simeng
