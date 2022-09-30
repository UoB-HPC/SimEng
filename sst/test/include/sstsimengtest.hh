#include "framework/macros/eval.hh"
#include "framework/macros/group.hh"
#include "framework/registry.hh"
#include "framework/runner.hh"
#include "framework/stats.hh"

#define RUN_ALL_TESTS()                                          \
  Registry* reg = Registry::getInstance();                       \
  auto map = reg->getMap();                                      \
  for (auto itr = map->begin(); itr != map->end(); itr++) {      \
    std::vector<Registry::Factory> fvec = itr->second;           \
    for (auto itrr = fvec.begin(); itrr != fvec.end(); itrr++) { \
      std::unique_ptr<Runner> rn = (*itrr)();                    \
      rn->run();                                                 \
    }                                                            \
  }                                                              \
  auto& stats = Stats::getInstance();                            \
  stats->printStats();                                           \
  if (stats->getFailureCount() > 0) {                            \
    exit(EXIT_FAILURE);                                          \
  }
