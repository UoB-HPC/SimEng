#pragma once

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>

#include <array>
#include <iostream>
#include <string>

#include "simeng/OS/Constants.hh"

namespace simeng {
namespace OS {

using namespace OS::defaults;

/** A FileDescEntry represents a host to virtual file descriptor mapping. */
class FileDescEntry {
 public:
  /** This constructor creates an empty file descriptor. */
  FileDescEntry(){};

  /** This constructor creates a file descriptor with a valid host fd. */
  FileDescEntry(int fd, int vfd, int flags, std::string filename)
      : fd_(fd), vfd_(vfd), flags_(flags), filename_(filename) {}

  /** This function returns the host file descriptor. */
  int getFd() { return fd_; };

  /** This function returns the virtual file descriptor. */
  int getVfd() { return vfd_; };

  /** This functions returns the flags associated with the host fd. */
  int getFlags() { return flags_; };

  /** This function returns the filename. */
  std::string getFilename() { return filename_; }

  /** This function is used to reset all properties of a FileDescEntry. It first
   * checks the validity of the current host fd, if the fd is still valid no
   * replacements are made. */
  bool replaceProps(int vfd, int fd, int flags, std::string filename) {
    if (fcntl(fd_, F_GETFD) != -1) {
      std::cerr
          << "[SimEng:FileDesc] File descriptor (" << fd_
          << ") for file: " << filename_
          << "is still valid. Cannot reset FileDescEntry with valid host fd."
          << std::endl;
      return false;
    }
    fd_ = fd;
    vfd_ = vfd;
    flags_ = flags;
    filename_ = filename;
    return true;
  };

  /** This function returns the validility of host fd, virtual fd and flags. */
  bool isValid() const { return (fd_ != -1 && vfd_ != -1 && flags_ != -1); }

 private:
  /** Host file descriptor. */
  int fd_ = -1;

  /** Virtual file descriptor. */
  int vfd_ = -1;

  /** Flags used in the openat syscall. */
  int flags_ = -1;

  /** Name of the opened file. */
  std::string filename_;
};

/** This class manages all the host to virtual file descriptor mappings. */
class FileDescArray {
 public:
  FileDescArray();

  ~FileDescArray();

  /** This function allocates a new FileDescEntry. It calls the host's openat
   * syscall with the specified parameters and maintains a host to virtual file
   * descriptor mapping. */
  int allocateFDEntry(int dirFD, const char* filename, int flags, int mode);

  /** This function returns an allocated FileDescEntry. If none is present
   * an empty FileDescEntry is returned. */
  const FileDescEntry& getFDEntry(int vfd) const;

  /** This function removes an allocated FileDescEntry. It calls the host's
   * close syscall with the fd corresponding to specified vfd. */
  int removeFDEntry(int vfd);

 private:
  /** Array which holds FileDescEntry(s) */
  std::array<FileDescEntry, MAX_FD_NUM> fdarr_;

  /** Number of FileDescEntry(s) in fdarr_ */
  uint64_t numFds_ = 0;

  /** Member function which validates the virtual file descriptor. */
  void validateVfd(int vfd) const;
};
}  // namespace OS
}  // namespace simeng
