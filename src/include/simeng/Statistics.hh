#pragma once

#include <algorithm>
#include <cassert>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>

#include "simeng/BuildMetadata.hh"

namespace simeng {

enum class statInsnType { NONE = 0, DUMP, RESET };

/** A class to maintain all statistics registered in SimEng. The class holds two
 * maps that holds many statistic event ids and their values, a full simulation
 * and simulation region map. The former records the values for each statistic
 * event over the ful simulation whilst the latter only the current region
 * defined by, pre-defined, statstic controlling instructions. */
class Statistics {
 public:
  Statistics(std::string outfile);
  ~Statistics();

  /** Register a statistic name and return an associated id. */
  uint64_t registerStat(std::string name);

  /** Increment a statistic by a given value. */
  void incrementStat(uint64_t id, uint64_t value);

  /** Get a full simulation statistic value by a given id. */
  uint64_t getFullSimStat(uint64_t id);

  /** Get a current region statistic value by a given id. */
  uint64_t getRegionStat(uint64_t id);

  /** Write current region statistics to the set outfile. */
  void dumpStats(uint64_t dumpAddress);

  /** Manually write a provided key, value pair to the outfile_. */
  void manualOutput(std::string key, std::string value);

  /** Reset all region statistics back to 0. */
  void resetStats();

  /** Fill the passed map with statistic from the simulation. */
  void fillSimulationStats(std::map<std::string, std::string>& statMap);

 private:
  /** Vector to hold statistic names. */
  std::vector<std::string> statNames_;

  /** Vector to hold statistic counters for entire simulation. */
  std::vector<uint64_t> fullSimulationStats_;

  /** Vector to hold region statistic counters. */
  std::vector<uint64_t> regionStats_;

  /** File to write statistics to. */
  std::ofstream outfile_;

  /** Number of statistics dumps made. */
  uint64_t dumpCounter_ = 0;
};

}  // namespace simeng
