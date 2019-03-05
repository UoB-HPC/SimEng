#pragma once

#include "capstone/capstone.h"

namespace simeng {

struct CapstoneInsn : cs_insn {
 public:
  CapstoneInsn() { detail = &detail_; }
  CapstoneInsn(const CapstoneInsn& other)
      : cs_insn(other), detail_(other.detail_) {
    detail = &detail_;
  }

 private:
  cs_detail detail_;
};

}  // namespace simeng
