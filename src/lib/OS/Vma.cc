#include "simeng/OS/Vma.hh"

#include <sys/stat.h>

#include <cstddef>

namespace simeng {
namespace OS {

HostFileMMap* HostBackedFileMMaps::mapfd(int fd, size_t size, off_t offset) {
  struct stat* statbuf = (struct stat*)malloc(sizeof(struct stat));
  if (fstat(fd, statbuf) < 0) {
    std::cerr << "(fstat failed): Cannot create host backed file mmap for file "
                 "descriptor: "
              << fd << std::endl;
    std::exit(1);
  };
  if (offset > statbuf->st_size) {
    std::cerr << "Tried to create host backed file mmap with offset greater "
                 "than file size."
              << fd << std::endl;
    std::exit(1);
  }
  size_t fsize = statbuf->st_size > size ? size : statbuf->st_size;
  if (fsize == 0) {
    std::cerr << "Cannot create host backed file mmap with size 0 for file "
                 "descriptor: "
              << fd << std::endl;
    std::exit(1);
  }
  void* filemmap =
      mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, offset);
  HostFileMMap* hfmm = new HostFileMMap(fd, filemmap, fsize, offset);
  hostvec.push_back(hfmm);
};

HostBackedFileMMaps::~HostBackedFileMMaps() {
  for (auto fmap : hostvec) {
    if (munmap(fmap->getfaddr(), fmap->fsize_) < 0) {
      std::cerr << "Unable to unmap host backed file mmap associated with file "
                   "descriptor: "
                << fmap->fd_ << std::endl;
      std::exit(1);
    }
    delete fmap;
  }
};

VirtualMemoryArea::VirtualMemoryArea(int fd, off_t offset, int prot, int flags,
                                     size_t vsize, VMAType type,
                                     HostFileMMap* hfmmap) {
  size = vsize;
  prot_ = prot;
  flags_ = flags;
  type_ = type;
  hfmmap_ = hfmmap;
  if (hfmmap != NULL) {
    filebuf_ = hfmmap->getfaddr();
    fsize_ = hfmmap->fsize_;
  }
};

VirtualMemoryArea::VirtualMemoryArea(VirtualMemoryArea* vma) {
  vm_start = vma->vm_start;
  vm_end = vma->vm_end;
  vm_next = vma->vm_next;
  flags_ = vma->flags_;
  prot_ = vma->prot_;
  hfmmap_ = vma->hfmmap_;
  size = vma->size;
  type_ = vma->type_;
  filebuf_ = vma->filebuf_;
  fsize_ = vma->fsize_;
};

VirtualMemoryArea::~VirtualMemoryArea(){};

// Address ranges are exclusive of the last address i.e [vm_start, vm_end)
bool VirtualMemoryArea::overlaps(uint64_t startAddr, size_t size) {
  uint64_t endAddr = startAddr + size;
  return (endAddr >= vm_start) && (startAddr < vm_end);
};

bool VirtualMemoryArea::contains(uint64_t startAddr, size_t size) {
  uint64_t endAddr = startAddr + size;
  return (startAddr >= vm_start) && (endAddr < vm_end);
};

bool VirtualMemoryArea::contains(uint64_t vaddr) {
  return (vaddr >= vm_start) && (vaddr < vm_end);
}

bool VirtualMemoryArea::containedIn(uint64_t startAddr, size_t size) {
  uint64_t endAddr = startAddr + size;
  return (startAddr <= vm_start) && (endAddr > vm_end);
};

void VirtualMemoryArea::trimRangeEnd(uint64_t addr) {
  size = addr - vm_start;
  vm_end = addr;
  // We dont host munmap here because addr and size have to page aligned, if
  // they are not we run the risk of unmapping a larger chunk of the file.
  // so we handle this in the destructor.
  if (hasFile()) fsize_ = fsize_ < size ? fsize_ : size;
};

void VirtualMemoryArea::trimRangeStart(uint64_t addr) {
  if (hasFile()) {
    size_t trimlen = addr - vm_start;
    if (trimlen >= fsize_) {
      // We dont host munmap here because addr and size have to page aligned, if
      // they are not we run the risk of unmapping a larger chunk of the file.
      // so we handle this in the destructor.
      filebuf_ = NULL;
      fsize_ = 0;
    } else {
      filebuf_ = (void*)filebuf_ + trimlen;
      fsize_ -= trimlen;
    }
  }
  size = vm_end - addr;
  vm_start = addr;
};

bool VirtualMemoryArea::hasFile() {
  return filebuf_ != nullptr && fsize_ != 0;
};

void* VirtualMemoryArea::getFileBuf() { return filebuf_; }

size_t VirtualMemoryArea::getFileSize() { return fsize_; }

}  // namespace OS
}  // namespace simeng
