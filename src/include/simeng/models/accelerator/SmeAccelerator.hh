#pragma once

#include "simeng/Accelerator.hh"
#include "simeng/pipeline/ExecuteUnit.hh"
#include "simeng/pipeline/PipelineBuffer.hh"

namespace simeng {
namespace models {
namespace accelerator {

class SmeAccelerator : public Accelerator {
 public:
  explicit SmeAccelerator(send_fn_t send_fn, receive_fn_t receive_fn,
                          bool pipelined = true,
                          const std::vector<uint16_t>& blockingGroups = {});

 protected:
  void tickImpl() override;

 private:
  pipeline::ExecuteUnit executeUnit_;
};

}  // namespace accelerator
}  // namespace models
}  // namespace simeng
