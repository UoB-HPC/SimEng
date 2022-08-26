#pragma once

#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>

namespace simeng {

enum class statInsnType { NONE = 0, DUMP, RESET };

/** A class to maintain all statistics registered in SimEng. */
class Statistics {
 public:
  Statistics(std::string outfile);
  ~Statistics();

  /** Register a statistic name and return an associated id. */
  uint64_t registerStat(std::string name);

  /** Increment a statistic by a given value. */
  void incrementStat(uint64_t id, uint64_t value);

  /** Write current region statistics to the set outfile. */
  void dumpStats(uint64_t dumpAddress);

  /** Manually write a provided key, value pair to the outfile_. */
  void manualOutput(std::string key, std::string value);

  /** Reset all region statistics back to 0. */
  void resetStats();

  /** Fill the passed map with general statistic form the full simulation. */
  void getGeneralSimulationStats(std::map<std::string, std::string>& statMap);

 private:
  /** Vector to hold statistic names. */
  std::vector<std::string> statNames_;

  /** Vector to hold region statistic counters. */
  std::vector<uint64_t> regionStats_;

  /** Vector to hold statistic counters for entire simulation. */
  std::vector<uint64_t> fullSimulationStats_;

  /** File to write statistics to. */
  std::ofstream outfile_;

  /** Number of statistics dumps made. */
  uint64_t dumpCounter_ = 0;
};

}  // namespace simeng
