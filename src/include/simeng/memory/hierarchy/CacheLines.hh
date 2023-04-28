#include <cstdint>
#include <memory>

#include "simeng/RegisterValue.hh"
#include "simeng/memory/MemPacket.hh"
#include "simeng/span.hh"

namespace simeng::memory::hierarchy {

class CacheLine {
 public:
  inline virtual uint32_t getTag() = 0;
  inline virtual bool isValid(uint16_t offset = 0) = 0;
  inline virtual bool isDirty(uint16_t offset = 0) = 0;
  inline virtual void setValid(uint16_t offset = 0) = 0;
  inline virtual void setDirty(uint16_t offset = 0) = 0;
  inline virtual void setInvalid(uint16_t offset = 0) = 0;
  inline virtual void setNotDirty(uint16_t offset = 0) = 0;
  /* virtual std::vector<char> load(uint16_t size, uint16_t offset = 0) = 0;
  virtual void write(std::vector<char> data, uint16_t size,
                     uint16_t offset = 0) = 0; */
};

struct UnSectoredCacheLine : public CacheLine {
 public:
  enum class CacheLineMasks : uint16_t {
    ValidMask = 0b1000000000000000,
    DirtyMask = 0b0100000000000000
  };

  inline uint32_t getTag() { return tag_; }
  inline bool isValid(uint16_t offset = 0) {
    return metadata_ & static_cast<uint16_t>(CacheLineMasks::ValidMask);
  }
  inline bool isDirty(uint16_t offset = 0) {
    return metadata_ & static_cast<uint16_t>(CacheLineMasks::DirtyMask);
  }
  inline void setValid(uint16_t offset = 0) {
    metadata_ = metadata_ | static_cast<uint16_t>(CacheLineMasks::ValidMask);
  }
  inline void setDirty(uint16_t offset = 0) {
    metadata_ = metadata_ | static_cast<uint16_t>(CacheLineMasks::DirtyMask);
  }
  inline void setInvalid(uint16_t offset = 0) {
    metadata_ = metadata_ & ~(static_cast<uint16_t>(CacheLineMasks::ValidMask));
  }
  inline void setNotDirty(uint16_t offset = 0) {
    metadata_ = metadata_ & ~(static_cast<uint16_t>(CacheLineMasks::DirtyMask));
  }

 private:
  uint64_t tag_;
  uint8_t metadata_;
  uint8_t* lineData_;
};

}  // namespace simeng::memory::hierarchy
