#pragma once

#include "simeng/Accelerator.hh"
#include "simeng/pipeline/ExecuteUnit.hh"
#include "simeng/pipeline/PipelineBuffer.hh"

namespace simeng {
namespace models {
namespace accelerator {

class SmeAccelerator : public Accelerator {
 public:
  explicit SmeAccelerator(id_t id, send_fn_t send_fn, receive_fn_t receive_fn,
                          bool pipelined = true,
                          const std::vector<uint16_t>& blockingGroups = {});

  /** An instruction filter which decides whether it should be offloaded
   * to the SME accelerator. */
  static bool shouldAccelerate(const std::shared_ptr<Instruction>& insn);

 protected:
  void tickImpl() override;

 private:
  /** Determines whether the provided register is a vector/matrix register. */
  static bool isSmeRegister(const Register& reg);

  pipeline::ExecuteUnit executeUnit_;
};

}  // namespace accelerator
}  // namespace models
}  // namespace simeng
