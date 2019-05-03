#pragma once

#include "../ArchitecturalRegisterFileSet.hh"

#include "RegisterAliasTable.hh"

namespace simeng {
namespace pipeline {

/** An ArchitecturalRegisterFileSet implementation which maps architectural
 * registers to their corresponding physical registers, according to a register
 * alias table's current mapping table. */
class MappedRegisterFileSet : public ArchitecturalRegisterFileSet {
 public:
  /** Create a mapped register file set which maps architectural registers to
   * their corresponding physical registers in `physicalRegisterFileSet`,
   * according to the mapping table in `rat`. */
  MappedRegisterFileSet(RegisterFileSet& physicalRegisterFileSet,
                        const RegisterAliasTable& rat);

  /** Read the value of the physical register currently mapped to the
   * architectural register `reg`.
   *
   * NOTE: The physical register mapped to depends on the current state of the
   * register alias table; if there are any allocated but uncommitted registers,
   * this mapping will not represent the committed architectural state. */
  virtual RegisterValue get(Register reg) const override;

  /** Set the physical register currently mapped to the architectural register
   * `reg` to the specified value.
   *
   * NOTE: The physical register mapped to depends on the current state of the
   * register alias table; if there are any allocated but uncommitted registers,
   * this mapping will not represent the committed architectural state. */
  virtual void set(Register reg, const RegisterValue& value) override;

 private:
  /** A reference to the register alias table to use for mapping architectural
   * to physical registers. */
  const RegisterAliasTable& rat_;
};

}  // namespace outoforder
}  // namespace simeng
