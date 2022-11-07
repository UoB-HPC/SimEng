#include <atomic>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>

#include "Json.hpp"

class Stats {
 private:
  std::unordered_map<uint64_t, uint64_t> read_lat_map_;
  std::unordered_map<uint64_t, uint64_t> write_lat_map_;
  std::atomic<uint64_t> total_read_count_ = std::atomic<uint64_t>(0);
  std::atomic<uint64_t> total_write_count_ = std::atomic<uint64_t>(0);
  std::atomic<uint64_t> total_read_split_count_ = std::atomic<uint64_t>(0);
  std::atomic<uint64_t> total_write_split_count_ = std::atomic<uint64_t>(0);
  std::atomic<uint64_t> l1_count_ = std::atomic<uint64_t>(0);
  std::atomic<uint64_t> l2_count_ = std::atomic<uint64_t>(0);
  std::atomic<uint64_t> mem_acc_count_ = std::atomic<uint64_t>(0);

  std::mutex read_lat_lk;
  std::mutex write_lat_lk;

 public:
  Stats(){};
  ~Stats(){};
  void recordWrite();
  void recordRead();
  void recordReadSplit(uint64_t count);
  void recordWriteSplit(uint64_t split);
  void dumpStats();
  void recordLoadAccessStart(uint64_t id, uint64_t cycle);
  void recordLoadAccessEnd(uint64_t id, uint64_t cycle);
  void recordMemoryHierarchyByLatency(uint64_t latency);
};