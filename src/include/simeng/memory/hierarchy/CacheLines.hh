#include <cstdint>
#include <cstring>
#include <memory>

#include "simeng/RegisterValue.hh"
#include "simeng/memory/MemPacket.hh"
#include "simeng/span.hh"

namespace simeng::memory::hierarchy {

/** The CacheLine class represent a cache line/cache block in SimEng. This is an
 * abstract class and it defines an API which any concrete implementation of a
 * cache line has to implement. All types of cache line/block need to inherit
 * this abstract class.  */
class CacheLine {
 public:
  /** Virtual destructor for the cache line. */
  virtual ~CacheLine();
  /** Function which returns the tag of the cache line. */
  inline virtual uint32_t getTag() = 0;
  /** Function which sets the tag of a cache line. */
  inline virtual void setTag(uint64_t tag) = 0;
  /** Function which returns the validity of a cache line. */
  inline virtual bool isValid(uint16_t offset = 0) = 0;
  /** Function which marks the cache line as valid. */
  inline virtual void setValid(uint16_t offset = 0) = 0;
  /** Function which marks the cache line as invalid. */
  inline virtual void setInvalid(uint16_t offset = 0) = 0;
  /** Function which returns whether a cache line is dirty or not. */
  inline virtual bool isDirty(uint16_t offset = 0) = 0;
  /** Function which marks the cache line as dirty. */
  inline virtual void setDirty(uint16_t offset = 0) = 0;
  /** Function which marks the cache line as not dirty. */
  inline virtual void setNotDirty(uint16_t offset = 0) = 0;
  /** Function which used to retrived pointer to cache array which holds cache
   * line data.*/
  inline virtual char* getData() = 0;
  /** Function which is used to supply data to the cache line. */
  virtual void supplyData(std::vector<char> data, uint16_t offset) = 0;
  /** Function which returns the starting pointer of the cache array which holds
   * the cache data. */
  inline virtual const char* begin() = 0;
  /** Function which returns the end pointer of the cache array which holds the
   * cache data. */
  inline virtual const char* end() = 0;
  /** Function which sets the starting physical address of the cache line. */
  inline virtual void setPaddr(uint64_t paddr) = 0;
  /** Function which gets the physical address of the cache line. */
  inline virtual uint64_t getPaddr() = 0;
  /** Function which checks if the cache line is busy. If a cache line is busy
   * it is used to indicate that the cache line is either being fetched from
   * memory or being evicted to memory. The information is important because it
   * is required by the MSHR to handle incoming requests to cache lines that are
   * being fetched or evicted. */
  inline virtual bool isBusy() = 0;
  /** Function which marks the cache line as busy. */
  inline virtual void setBusy() = 0;
  /** Function which marks the cache line as not busy. */
  inline virtual void setNotBusy() = 0;
};

struct UnSectoredCacheLine : public CacheLine {
 public:
  /** Enum which holds masks needed for UnSectoredCacheLine operation.. */
  enum class CacheLineMasks : uint16_t {
    ValidMask = 0b1000000000000000,
    DirtyMask = 0b0100000000000000,
    BusyMask = 0b0010000000000000,
  };

  /** Constructor for the UnSectoredCacheLine. */
  UnSectoredCacheLine(uint32_t size) : size_(size) {
    lineData_ = new char(size);
  }
  /** Destructor for the UnSectoredCacheLine. */
  ~UnSectoredCacheLine() { delete lineData_; }
  /** Function which returns the tag of the cache line. */
  inline uint32_t getTag() override { return tag_; }
  /** Function which sets the tag of a cache line. */
  inline void setTag(uint64_t tag) override { tag_ = tag; }
  /** Function which returns the validity of a cache line. */
  inline bool isValid(uint16_t offset = 0) override {
    return metadata_ & static_cast<uint16_t>(CacheLineMasks::ValidMask);
  }
  /** Function which returns whether a cache line is dirty or not. */
  inline bool isDirty(uint16_t offset = 0) override {
    return metadata_ & static_cast<uint16_t>(CacheLineMasks::DirtyMask);
  }
  /** Function which marks the cache line as valid. */
  inline void setValid(uint16_t offset = 0) override {
    metadata_ = metadata_ | static_cast<uint16_t>(CacheLineMasks::ValidMask);
  }
  /** Function which marks the cache line as dirty. */
  inline void setDirty(uint16_t offset = 0) override {
    metadata_ = metadata_ | static_cast<uint16_t>(CacheLineMasks::DirtyMask);
  }
  /** Function which marks the cache line as invalid. */
  inline void setInvalid(uint16_t offset = 0) override {
    tag_ = -1;
    metadata_ = metadata_ & ~(static_cast<uint16_t>(CacheLineMasks::ValidMask));
  }
  /** Function which marks the cache line as not dirty. */
  inline void setNotDirty(uint16_t offset = 0) override {
    metadata_ = metadata_ & ~(static_cast<uint16_t>(CacheLineMasks::DirtyMask));
  }
  /** Function which used to retrived pointer to cache array which holds cache
   * line data.*/
  inline char* getData() override { return lineData_; };
  /** Function which returns the starting pointer of the cache array which holds
   * the cache data. */
  inline const char* begin() override { return lineData_; }
  /** Function which returns the end pointer of the cache array which holds the
   * cache data. */
  inline const char* end() override { return lineData_ + size_; }
  /** Function which sets the starting physical address of the cache line. */
  inline void setPaddr(uint64_t paddr) override { paddr_ = paddr; }
  /** Function which sets the starting physical address of the cache line. */
  inline uint64_t getPaddr() override { return paddr_; }
  /** Function which is used to supply data to the cache line. */
  void supplyData(std::vector<char> data, uint16_t offset) override {
    std::memcpy(lineData_ + offset, data.data(), data.size());
  };
  /** Function which checks if the cache line is busy. If a cache line is busy
   * it is used to indicate that the cache line is either being fetched from
   * memory or being evicted to memory. The information is important because it
   * is required by the MSHR to handle incoming requests to cache lines that are
   * being fetched or evicted. */
  inline bool isBusy() override {
    return metadata_ & static_cast<uint16_t>(CacheLineMasks::BusyMask);
  }
  /** Function which marks the cache line as busy. */
  inline void setBusy() override {
    metadata_ = metadata_ | static_cast<uint16_t>(CacheLineMasks::BusyMask);
  }
  /** Function which marks the cache line as not busy. */
  inline void setNotBusy() override {
    metadata_ = metadata_ & ~(static_cast<uint16_t>(CacheLineMasks::BusyMask));
  }

 private:
  /** The char array which holds the data of the cache line. */
  char* lineData_;
  /** The physical address of the data stored in the cache line */
  uint64_t paddr_ = 0;
  /** The tag of the cache line. */
  uint64_t tag_ = -1;
  /** The size of the cache line, this is an alias of cache line width. */
  uint32_t size_ = 0;
  /** The metadata variable stores the following information regarding the cache
   * line (MSB to LSB):
   *  1) The 16th bit indicates if the cache is valid or not.
   *  2) The 15th bit indicates if the cache line is dirty or not.
   *  3) The 14th bit indicates if the cache line is busy or not. */
  uint16_t metadata_ = 0;
};

}  // namespace simeng::memory::hierarchy
