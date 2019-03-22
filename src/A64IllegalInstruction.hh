#pragma once

#include "A64ExceptionGenerator.hh"
#include "Instruction.hh"

namespace simeng {

class A64IllegalInstruction : public Instruction, public A64ExceptionGenerator {
 public:
  A64IllegalInstruction(uint64_t encoding);

  A64InstructionException getException() const override;

  const span<Register> getOperandRegisters() const override;
  const span<Register> getDestinationRegisters() const override;
  bool isOperandReady(int index) const override;

  /** Override the specified source register with a renamed physical register.
   */
  void renameSource(uint8_t i, Register renamed) override;

  /** Override the specified destination register with a renamed physical
   * register. */
  void renameDestination(uint8_t i, Register renamed) override;

  /** Provide a value for the specified physical register. */
  void supplyOperand(const Register& reg, const RegisterValue& value) override;

  /** Check whether all operand values have been supplied, and the instruction
   * is ready to execute. */
  bool canExecute() const override;

  /** Execute the instruction. */
  void execute() override;

  /** Retrieve register results. */
  const span<RegisterValue> getResults() const override;

  /** Generate memory addresses this instruction wishes to access. */
  std::vector<std::pair<uint64_t, uint8_t>> generateAddresses() override;

  /** Retrieve previously generated memory addresses. */
  std::vector<std::pair<uint64_t, uint8_t>> getGeneratedAddresses()
      const override;

  /** Provide data from a requested memory address. */
  void supplyData(uint64_t address, const RegisterValue& data) override;

  /** Retrieve supplied memory data. */
  std::vector<RegisterValue> getData() const override;

  /** Early misprediction check; see if it's possible to determine whether the
   * next instruction address was mispredicted without executing the
   * instruction. */
  std::tuple<bool, uint64_t> checkEarlyBranchMisprediction() const override;

  /** Is this a store operation? */
  bool isStore() const override;

  /** Is this a load operation? */
  bool isLoad() const override;

  /** Is this a branch operation? */
  bool isBranch() const override;

  /** Get the instruction's group. */
  uint16_t getGroup() const override;

 private:
  uint64_t encoding_;
};

}  // namespace simeng
