<<<<<<< HEAD
<<<<<<< HEAD
#include <errno.h>
#include <fcntl.h>
=======
>>>>>>> c36c82eb (added PageArameAllocator decl)
=======
>>>>>>> 76a7cd60 (added pfalloc file)
#include <stdint.h>
#include <sys/stat.h>

#include <array>
<<<<<<< HEAD
<<<<<<< HEAD
#include <iostream>
#include <string>
=======
>>>>>>> c36c82eb (added PageArameAllocator decl)
=======
>>>>>>> 76a7cd60 (added pfalloc file)

#define MAX_FD_NUM 1024

/** A FileDescEntry represents a host to virtual file descriptor mapping. */
struct FileDescEntry {
<<<<<<< HEAD
<<<<<<< HEAD
 public:
  FileDescEntry(){};

  FileDescEntry(int fd, int vfd, int flags, std::string filename)
      : fd_(fd), vfd_(vfd), flags_(flags), filename_(filename) {}

  /** This function returns the host file descriptor. */
  int fd() { return fd_; };

  /** This function returns the virtual file descriptor. */
  int vfd() { return vfd_; };

  /** This functions returns the flags associated with the host fd. */
  int flags() { return flags_; };

  /** This function return the filename. */
  std::string filename() { return filename_; }

  /** This function is used to reset all properties of a FileDescEntry. */
  bool reset(int vfd, int fd, int flags, std::string filename) {
    if (fcntl(fd_, F_GETFD) != -1) {
      std::cerr
          << "File descriptor (" << fd_ << ") for file: " << filename_
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

  /** This function returns true if FileDescEntry doesn't contain a valid fd. */
  bool isValid() { return (fd_ != -1 && vfd_ != -1 && flags_ != -1); }

 private:
  /** Host file descriptor. */
  int fd_ = -1;

  /** Virtual file descriptor. */
  int vfd_ = -1;

  /** Flags used in the openat syscall. */
  int flags_ = -1;

  /** Name of the opened file. */
  std::string filename_;
=======
=======
>>>>>>> 76a7cd60 (added pfalloc file)
  /** Host file descriptor. */
  const int fd_;
  /** Virtual file descriptor. */
  const int vfd_;
  /** Flags used in the openat syscall. */
  const int flags_;
  /** Name of the opened file. */
  const char* filename_;
  FileDescEntry(int fd, int vfd, int flags, const char* filename)
      : fd_(fd), vfd_(vfd), flags_(flags), filename_(filename) {}
<<<<<<< HEAD
>>>>>>> c36c82eb (added PageArameAllocator decl)
=======
>>>>>>> 76a7cd60 (added pfalloc file)
};

/** This class managed the all host to virtual file descriptor mappings. */
class FileDescArray {
<<<<<<< HEAD
<<<<<<< HEAD
 public:
  FileDescArray();

  ~FileDescArray();

  /**
   * This function allocates a new FileDescEntry. It calls the host's openat
   * syscall with the specified parameters and maintains a host to virtual file
   * descriptor mapping.
   */
  int allocateFDEntry(int dirFD, const char* filename, int flags, int mode);

  /**
   * This function returns an allocated FileDescEntry. If none is present
   * nullptr is returned.
   */
  FileDescEntry& getFDEntry(int vfd);

  /**
   * This function removes an allocated FileDescEntry. It calls the host's close
   * syscall with the fd corresponding to specified vfd.
   */
  int removeFDEntry(int vfd);

=======
>>>>>>> c36c82eb (added PageArameAllocator decl)
=======
>>>>>>> 76a7cd60 (added pfalloc file)
 private:
  /**
   * Maximum number of file descriptors per process, defined by the linux
   * kernel.
   */
  static const uint64_t maxFdNum_ = 1024;

  /** Array which holds FileDescEntry(s) */
<<<<<<< HEAD
<<<<<<< HEAD
  std::array<FileDescEntry, maxFdNum_> fdarr_;
=======
  std::array<FileDescEntry*, maxFdNum_> fdarr_;
>>>>>>> c36c82eb (added PageArameAllocator decl)
=======
  std::array<FileDescEntry*, maxFdNum_> fdarr_;
>>>>>>> 76a7cd60 (added pfalloc file)

  /** Number of FileDescEntry(s) in fdarr_ */
  uint64_t numFds_ = 0;

  /**
   * Member function which validates virtual file descriptor. Default value
   * (-1) check validates size of fdarr_.
   */
  void validate(int vfd = -1);
<<<<<<< HEAD
<<<<<<< HEAD
};
=======
=======
>>>>>>> 76a7cd60 (added pfalloc file)

 public:
  FileDescArray();
  ~FileDescArray();
  /**
   * This function allocates a new FileDescEntry. It calls the host's openat
   * syscall with the specified parameters and maintains a host to virtual file
   * descriptor mapping.
   */
  int allocateFDEntry(int dirFD, const char* filename, int flags, int mode);
  /**
   * This function returns an allocated FileDescEntry. If none is present
   * nullptr is returned.
   */
  FileDescEntry* getFDEntry(int vfd);
  /**
   * This function removes an allocated FileDescEntry. It calls the host's close
   * syscall with the fd corresponding to specified vfd.
   */
  int removeFDEntry(int vfd);
<<<<<<< HEAD
};
>>>>>>> c36c82eb (added PageArameAllocator decl)
=======
};
>>>>>>> 76a7cd60 (added pfalloc file)
