#include <map>
#include <memory>
namespace simeng {
namespace OS {

struct PTEntry {
  uint64_t vaddr;
  uint64_t physAddr;
  uint64_t size;
};

class PageTable {
 private:
  uint32_t pageSize_;
  std::shared_ptr<std::map<uint64_t, PTEntry*>> table_;

  bool allocatePTEntry(uint64_t addr);
  uint64_t calculateOffset(uint64_t vaddr, uint64_t physfStartAddr);

 public:
  PageTable();
  ~PageTable();
  bool isAddrAllocated(uint64_t addr, uint64_t size);
};

}  // namespace OS
}  // namespace simeng
