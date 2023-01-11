#include <stdint.h>
#include <sys/stat.h>

#include <array>

#define MAX_FD_NUM 1024

/** A FileDescEntry represents a host to virtual file descriptor mapping. */
struct FileDescEntry {
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
};

/** This class managed the all host to virtual file descriptor mappings. */
class FileDescArray {
 private:
  /**
   * Maximum number of file descriptors per process, defined by the linux
   * kernel.
   */
  static const uint64_t maxFdNum_ = 1024;

  /** Array which holds FileDescEntry(s) */
  std::array<FileDescEntry*, maxFdNum_> fdarr_;

  /** Number of FileDescEntry(s) in fdarr_ */
  uint64_t numFds_ = 0;

  /**
   * Member function which validates virtual file descriptor. Default value
   * (-1) check validates size of fdarr_.
   */
  void validate(int vfd = -1);

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
};