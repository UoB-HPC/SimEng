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
  virtual char* getData() = 0;
  virtual void supplyData(std::vector<char> data, uint16_t offset) = 0;
  virtual const char* begin() = 0;
  virtual const char* end() = 0;
  virtual void setPaddr(uint64_t paddr) = 0;
  virtual uint64_t getPaddr() = 0;
  virtual bool isBusy() = 0;
  virtual void setBusy() = 0;
  virtual void setNotBusy() = 0;
};

struct UnSectoredCacheLine : public CacheLine {
 public:
  enum class CacheLineMasks : uint16_t {
    ValidMask = 0b1000000000000000,
    DirtyMask = 0b0100000000000000,
    EvictionMask = 0b0010000000000000,
    BusyMask = 0b0001000000000000,
  };

  UnSectoredCacheLine(uint32_t size) : size_(size) {
    lineData_ = new char(size);
  }

  inline uint32_t getTag() override { return tag_; }
  inline void setTag(uint64_t tag) override { tag_ = tag; }
  inline bool isValid(uint16_t offset = 0) override {
    return metadata_ & static_cast<uint16_t>(CacheLineMasks::ValidMask);
  }
  inline bool isDirty(uint16_t offset = 0) override {
    return metadata_ & static_cast<uint16_t>(CacheLineMasks::DirtyMask);
  }
  inline void setValid(uint16_t offset = 0) override {
    metadata_ = metadata_ | static_cast<uint16_t>(CacheLineMasks::ValidMask);
  }
  inline void setDirty(uint16_t offset = 0) override {
    metadata_ = metadata_ | static_cast<uint16_t>(CacheLineMasks::DirtyMask);
  }
  inline void setInvalid(uint16_t offset = 0) override {
    tag_ = -1;
    metadata_ = metadata_ & ~(static_cast<uint16_t>(CacheLineMasks::ValidMask));
  }
  inline void setNotDirty(uint16_t offset = 0) override {
    metadata_ = metadata_ & ~(static_cast<uint16_t>(CacheLineMasks::DirtyMask));
  }
  inline void setInEviction() {
    metadata_ = metadata_ | static_cast<uint16_t>(CacheLineMasks::EvictionMask);
  }
  char* getData() override { return lineData_; };
  const char* begin() override { return lineData_; }

  const char* end() override { return lineData_ + size_; }

  void setPaddr(uint64_t paddr) override { paddr_ = paddr; }

  uint64_t getPaddr() override { return paddr_; }

  void supplyData(std::vector<char> data, uint16_t offset) override {
    std::memcpy(lineData_ + offset, data.data(), data.size());
  };

  bool isBusy() override {
    return metadata_ & static_cast<uint16_t>(CacheLineMasks::BusyMask);
  }

  void setBusy() override {
    metadata_ = metadata_ | static_cast<uint16_t>(CacheLineMasks::BusyMask);
  }

  void setNotBusy() override {
    metadata_ = metadata_ & ~(static_cast<uint16_t>(CacheLineMasks::BusyMask));
  }

 private:
  char* lineData_;
  uint64_t paddr_ = 0;
  uint64_t tag_ = -1;
  uint32_t size_ = 0;
  uint16_t metadata_ = 0;
};

}  // namespace simeng::memory::hierarchy
