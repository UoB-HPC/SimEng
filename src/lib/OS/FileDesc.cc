
#include "simeng/OS/FileDesc.hh"

#include <stdlib.h>
#include <unistd.h>

namespace simeng {
namespace OS {

FileDescArray::FileDescArray() {
  // Value for flags were determined using fstat.
  // Here we initliase 3 FileDescEntry(s) which correspond to default IO file
  // descriptors.
  fdarr_[0].replaceProps(0, STDIN_FILENO, 0, "stdin");
  fdarr_[1].replaceProps(1, STDOUT_FILENO, 0, "stdout");
  fdarr_[2].replaceProps(2, STDERR_FILENO, 0, "stderr");
  numFds_ = 3;
}

void FileDescArray::validateVfd(int vfd) const {
  if (vfd < 0 || vfd > MAX_FD_NUM) {
    std::cerr << "[SimEng:FileDescArray] Invalid virtual file descriptor: "
              << vfd << std::endl;
    std::exit(1);
  }
}

int FileDescArray::allocateFDEntry(int dirfd, const char* filename, int flags,
                                   int mode) {
  // if numFds_ >= MAX_FD_NUM then there no space left for FileDescEntry(s).
  if (numFds_ == MAX_FD_NUM) {
    std::cerr << "[SimEng:FileDescArray] Maximum number of file descriptors "
                 "allocated."
              << std::endl;
    std::exit(1);
  }

  for (int i = 0; fdarr_.max_size(); i++) {
    if (!fdarr_[i].isValid()) {
      int fd = ::openat(dirfd, filename, flags, mode);
      if (fd == -1) {
        std::cerr << "[SimEng:FileDescArray] Error opening file at pathname: "
                  << filename << std::endl;
        return -1;
      }
      if (!fdarr_[i].replaceProps(i, fd, flags, std::string(filename))) {
        std::cerr << "[SimEng:FileDescArray] Error occured while replacing "
                     "FileDescEntry."
                  << std::endl;
        return -1;
      }
      numFds_++;
      return i;
    }
  }
  std::cerr << "[SimEng:FileDescArray] The number of active file descriptors: "
            << numFds_
            << " is less than the maximum number of file descriptors allowed: "
            << MAX_FD_NUM
            << " However, all the FileDescArray(s) in fdarr_ "
               "are valid, which prevents allocation of new entry."
            << std::endl;
  std::exit(1);
}

const FileDescEntry& FileDescArray::getFDEntry(int vfd) const {
  validateVfd(vfd);
  if (!fdarr_[vfd].isValid()) {
    std::cerr << "[SimEng:FileDescArray] Virtual file descriptor (" << vfd
              << ") does not correspond to a file "
                 "descriptor"
              << std::endl;
  }
  return fdarr_[vfd];
}

int FileDescArray::removeFDEntry(int vfd) {
  validateVfd(vfd);
  FileDescEntry entry = fdarr_[vfd];
  if (!entry.isValid()) {
    std::cerr << "[SimEng:FileDescArray] Virtual file descriptor does not "
                 "correspond to a file descriptor. "
              << vfd << std::endl;
    return EBADF;
  }
  if (close(entry.getFd()) == -1) {
    std::cerr << "[SimEng:FileDescArray] Error closing file with filename:  "
              << entry.getFilename() << std::endl;
    return EBADF;
  }

  // Here all properties of the FileDescEntry are reset to default values and
  // this is considered as a removal.
  if (!fdarr_[vfd].replaceProps(-1, -1, -1, "")) {
    std::cerr << "[SimEng:FileDescArray] Error occured while replacing "
                 "FileDescEntry"
              << std::endl;
    return EBADF;
  }
  numFds_--;
  return 0;
}

FileDescArray::~FileDescArray() {
  // Close any remaining unclosed file descriptors.
  for (uint64_t i = 3; i < fdarr_.max_size(); i++) {
    if (fdarr_[i].isValid()) {
      if (close(fdarr_[i].getFd()) == -1) {
        std::cerr
            << "[SimEng:FileDescArray] Error closing file with filename:  "
            << fdarr_[i].getFilename() << std::endl;
      }
    }
  }
}

}  // namespace OS
}  // namespace simeng
