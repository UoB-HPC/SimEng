
#include "simeng/OS/FileDesc.hh"

#include <stdlib.h>
#include <unistd.h>

FileDescArray::FileDescArray() {
  // Value for flags were determined using fstat.
  fdarr_[0].reset(0, STDIN_FILENO, 0, "stdin");
  fdarr_[1].reset(1, STDOUT_FILENO, 0, "stdout");
  fdarr_[2].reset(2, STDERR_FILENO, 0, "stderr");
  numFds_ = 3;
}

void FileDescArray::validate(int vfd) {
  if (numFds_ >= maxFdNum_) {
    std::cerr << "Maximum number of file descriptors allocated." << std::endl;
    std::exit(1);
  }
  if (vfd == -1) return;
  if (vfd > maxFdNum_) {
    std::cerr << "Invalid virtual file descriptor: " << vfd << std::endl;
    std::exit(1);
  }
}

int FileDescArray::allocateFDEntry(int dirfd, const char* filename, int flags,
                                   int mode) {
  validate();
  for (int i = 0; fdarr_.max_size(); i++) {
    if (!fdarr_[i].isValid()) {
      int fd = openat(dirfd, filename, flags, mode);
      if (fd == -1) {
        std::cerr << "Error opening file at pathname: " << filename
                  << std::endl;
        return -1;
      }
      if (!fdarr_[i].reset(i, fd, flags, std::string(filename))) {
        std::cerr << "Error occured while resetting FileDescEntry."
                  << std::endl;
      };
      this->numFds_++;
      return i;
    }
  }
  return -1;
}

FileDescEntry& FileDescArray::getFDEntry(int vfd) {
  validate(vfd);
  if (!fdarr_[vfd].isValid()) {
    std::cerr << "Virtual file descriptor (" << vfd
              << ") does not correspond to a file "
                 "descriptor"
              << std::endl;
  }
  return fdarr_[vfd];
}

int FileDescArray::removeFDEntry(int vfd) {
  validate(vfd);
  FileDescEntry entry = fdarr_[vfd];
  if (!entry.isValid()) {
    std::cerr
        << "Virtual file description does not correspond to a file descriptor. "
        << vfd << std::endl;
    return EBADF;
  }
  if (close(entry.fd()) == -1) {
    std::cerr << "Error closing file with filename:  " << entry.filename()
              << std::endl;
    return -1;
  };

  if (!fdarr_[vfd].reset(-1, -1, -1, "")) {
    std::cerr << "Error occured while resetting FileDescEntry" << std::endl;
    std::exit(1);
  };
  this->numFds_--;
  return 0;
}

FileDescArray::~FileDescArray() {
  // Close any remaining unclosed file descriptors.
  for (uint64_t i = 3; i < fdarr_.max_size(); i++) {
    if (fdarr_[i].isValid()) {
      if (close(fdarr_[i].fd()) == -1) {
        std::cerr << "Error closing file with filename:  "
                  << fdarr_[i].filename() << std::endl;
      };
    }
  }
}
