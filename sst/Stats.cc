#include "Stats.hh"

void Stats::recordRead() { total_read_count_++; };
void Stats::recordWrite() { total_write_count_++; };
void Stats::recordReadSplit(uint64_t count) {
  total_read_split_count_ += count;
};
void Stats::recordWriteSplit(uint64_t count) {
  total_write_split_count_ += count;
};

void Stats::dumpStats() {
  nlohmann::json j;
  std::ofstream output_file("sstsimeng-stats.json");
  j["total_read_requests"] = total_read_count_.load();
  j["total_write_count"] = total_write_count_.load();
  j["total_memory_requests"] =
      total_read_count_.load() + total_write_count_.load();
  j["total_read_split_requests"] = total_read_split_count_.load();
  j["total_write_split_requests"] = total_write_split_count_.load();
  j["total_split_count"] =
      total_read_split_count_.load() + total_write_split_count_.load();
  j["total_L1_access"] = l1_count_.load();
  j["total_L2_access"] = l2_count_.load();
  j["total_mem_access"] = mem_acc_count_.load();
  output_file << std::setw(4) << j << std::endl;
  output_file.close();
}

void Stats::recordLoadAccessStart(uint64_t id, uint64_t cycle) {
  std::lock_guard<std::mutex> grd(read_lat_lk);
  auto itr = read_lat_map_.find(id);
  if (itr != read_lat_map_.end()) {
    std::cerr << "Id in read latency map found on access." << std::endl;
    exit(1);
  }
  read_lat_map_.insert({id, cycle});
}

void Stats::recordLoadAccessEnd(uint64_t id, uint64_t cycle) {
  std::lock_guard<std::mutex> grd(read_lat_lk);
  auto itr = read_lat_map_.find(id);
  if (itr == read_lat_map_.end()) {
    std::cerr << "Id in read latency map not found in access end." << std::endl;
    exit(1);
  }
  uint64_t latency = cycle - itr->second;
  recordMemoryHierarchyByLatency(latency);
}

void Stats::recordMemoryHierarchyByLatency(uint64_t latency) {
  if (latency <= 0) {
    std::cerr << "Memory access latency less or equal to zero!" << std::endl;
    exit(1);
  }
  if (latency < 85) {
    l1_count_++;
    return;
  }
  // Extra for mshr latency
  if (latency < 170) {
    l2_count_++;
    return;
  }
  mem_acc_count_++;
}