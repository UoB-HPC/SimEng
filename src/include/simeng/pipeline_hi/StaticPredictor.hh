#pragma once

#include <deque>

#include "simeng/BranchPredictor.hh"
#include "yaml-cpp/yaml.h"

namespace simeng {
namespace pipeline_hi {

/** A static branch predictor; configurable in YAML config
 */
class StaticPredictor : public BranchPredictor {
 public:
  StaticPredictor(uint8_t sType);  // TODO: temp constructor, get rid of yaml,
                                   // delete it later
  StaticPredictor(YAML::Node config);
  ~StaticPredictor();

  BranchPrediction predict(uint64_t address, BranchType type,
                           uint64_t knownTarget, uint8_t byteLength) override;

  /** Generate a branch prediction for the specified instruction address; will
   * behave based on the configuration  */
  BranchPrediction predict(uint64_t address, BranchType type,
                           uint64_t knownTarget) override;

  /** Provide branch results to update the prediction model for the specified
   * instruction address. As this model is static, this does nothing. */
  void update(uint64_t address, bool taken, uint64_t targetAddress,
              BranchType type) override;

  /** Provide flush logic for branch prediction scheme. The behaviour will
   * be based on the configuration */
  void flush(uint64_t address) override;

 private:
  /** Decide which static predictor will be in use */
  uint8_t staticType_;

  /** A return address stack. */
  std::deque<uint64_t> ras_;

  /** RAS history with instruction address as the keys. A non-zero value
   * represents the target prediction for a return instruction and a 0 entry for
   * a branch-and-link instruction. */
  std::map<uint64_t, uint64_t> rasHistory_;

  /** The size of the RAS. */
  uint64_t rasSize_ = 1000;
};

}  // namespace pipeline_hi
}  // namespace simeng
