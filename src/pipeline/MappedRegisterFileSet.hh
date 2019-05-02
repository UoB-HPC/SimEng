#pragma once

#include "../ArchitecturalRegisterFileSet.hh"

#include "RegisterAliasTable.hh"

namespace simeng {
namespace pipeline {

class MappedRegisterFileSet : public ArchitecturalRegisterFileSet {
 public:
  MappedRegisterFileSet(RegisterFileSet& physicalRegisterFileSet,
                        const RegisterAliasTable& rat);

  /** Read the value of the specified register. */
  virtual RegisterValue get(Register reg) const override;

  /** Set a register as the specified value. */
  virtual void set(Register reg, const RegisterValue& value) override;

 private:
  const RegisterAliasTable& rat_;
};

}  // namespace outoforder
}  // namespace simeng
