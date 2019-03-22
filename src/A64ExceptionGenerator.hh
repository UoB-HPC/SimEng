#pragma once

namespace simeng {

enum class A64InstructionException {
  None = 0,
  EncodingUnallocated,
  EncodingNotYetImplemented,
  ExecutionNotYetImplemented
};

class A64ExceptionGenerator {
 public:
  virtual ~A64ExceptionGenerator(){};

  virtual A64InstructionException getException() const = 0;
};

}  // namespace simeng
