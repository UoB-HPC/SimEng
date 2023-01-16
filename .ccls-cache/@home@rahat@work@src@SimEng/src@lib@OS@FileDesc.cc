
#include "simeng/OS/FileDesc.hh"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>

FileDescArray::FileDescArray() {
  fdarr_.fill(nullptr);
  // Value for flags were determined using fstat.
  fdarr_[0] = new FileDescEntry{STDIN_FILENO, 0, 0, "stdin"};
  fdarr_[1] = new FileDescEntry{STDOUT_FILENO, 1, 0, "stdout"};
  fdarr_[2] = new FileDescEntry{STDERR_FILENO, 2, 0, "stderr"};
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
  for (size_t i = 0; fdarr_.max_size(); i++) {
    if (fdarr_[i] == nullptr) {
      int fd = openat(dirfd, filename, flags, mode);
      if (fd == -1) {
        std::cerr << "Error opening file at pathname: " << filename
                  << std::endl;
        return -1;
      }
      fdarr_[i] = new FileDescEntry{fd, i, flags, filename};
      this->numFds_++;
      return i;
    }
  }
}

FileDescEntry* FileDescArray::getFDEntry(int vfd) {
  validate(vfd);
  FileDescEntry* entry = fdarr_[vfd];
  if (entry == nullptr) {
    std::cerr << "Virtual file descriptor (" << vfd
              << ") does not correspond to a file "
                 "descriptor"
              << std::endl;
    return nullptr;
  }
  return entry;
}

int FileDescArray::removeFDEntry(int vfd) {
  validate(vfd);
  FileDescEntry* entry = fdarr_[vfd];
  if (entry == nullptr) {
    std::cerr
        << "Virtual file description does not correspond to a file descriptor. "
        << vfd << std::endl;
    return EBADF;
  }
  if (close(entry->fd_) == -1) {
    std::cerr << "Error closing file with filename:  " << entry->filename_
              << std::endl;
    return -1;
  };

  fdarr_[vfd] = nullptr;
  delete entry;
  this->numFds_--;
  return 0;
}

FileDescArray::~FileDescArray() {
  // Don't close STD file descriptors.
  FileDescEntry* entry;
  entry = fdarr_[0];
  delete entry;
  fdarr_[0] = nullptr;

  entry = fdarr_[1];
  delete entry;
  fdarr_[1] = nullptr;

  entry = fdarr_[2];
  delete entry;
  fdarr_[2] = nullptr;

  // Close any remaining unclosed file descriptors.
  for (uint64_t i = 0; i < fdarr_.max_size(); i++) {
    if (fdarr_[i] != nullptr) {
      entry = fdarr_[i];
      if (close(entry->fd_) == -1) {
        std::cerr << "Error closing file with filename:  " << entry->filename_
                  << std::endl;
      };
      delete entry;
      fdarr_[i] = nullptr;
    }
  }
}
