#include "framework/macros/eval.hh"
#include "framework/macros/group.hh"
#include "framework/parser.hh"
#include "framework/registry.hh"
#include "framework/runner.hh"
#include "framework/stats.hh"

inline std::string appendBinDirPath(std::string binName) {
  return ("execBin=" + std::string(SST_TEST_DIR) + "/sstbinaries/" + binName);
}