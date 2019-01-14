#ifndef __H_A64_INSTRUCTION
#define __H_A64_INSTRUCTION

#include <unordered_map>

#include "instruction.hh"

namespace simeng {

namespace A64RegisterType {
const uint8_t GENERAL = 0;
const uint8_t VECTOR = 1;
const uint8_t NZCV = 2;
}  // namespace A64RegisterType

typedef struct {
  uint8_t sf;
  uint8_t N;
  union {
    uint64_t imm;
    int64_t offset;
  };
  bool wback;
  bool postindex;
  uint8_t scale;
  uint8_t cond;
} A64DecodeMetadata;

enum A64InstructionException {
  None = 0,
  EncodingUnallocated,
  EncodingNotYetImplemented,
  ExecutionNotYetImplemented
};

enum class A64Opcode {
  B,
  B_cond,
  LDR_I,
  ORR_I,
  STR_I,
  SUB_I,
  SUBS_I,
};

typedef struct {
  RegisterValue value;
} A64Result;

class A64Instruction : public Instruction {
 public:
  static std::vector<std::shared_ptr<Instruction>> decode(
      void *encoding, uint64_t instructionAddress);

  A64Instruction(){};
  A64Instruction(uint32_t insn, uint64_t instructionAddress);

  InstructionException getException() const override;

  const std::vector<Register> &getOperandRegisters() const override;
  const std::vector<Register> &getDestinationRegisters() const override;

  bool isOperandReady(int index) const override;

  void rename(const std::vector<Register> &destinations,
              const std::vector<Register> &operands) override;

  void supplyOperand(const Register &reg, const RegisterValue &value) override;
  bool canExecute() const override;

  void execute() override;
  bool canCommit() const override;

  std::vector<RegisterValue> getResults() const override;

  std::vector<std::pair<uint64_t, uint8_t>> generateAddresses() override;
  std::vector<std::pair<uint64_t, uint8_t>> getGeneratedAddresses() const override;

  void supplyData(uint64_t address, const RegisterValue &data) override;
  std::vector<RegisterValue> getData() const override;

  bool wasBranchMispredicted() const override;
  uint64_t getBranchAddress() const override;

  bool isStore() const override;
  bool isLoad() const override;
  bool isBranch() const override;

  static const Register ZERO_REGISTER;
  static std::unordered_map<uint32_t, A64Instruction> decodeCache;

 private:
  A64Opcode opcode;
  uint64_t instructionAddress;
  A64DecodeMetadata metadata;

  std::vector<Register> sourceRegisters;
  std::vector<Register> destinationRegisters;

  std::vector<RegisterValue> operands;
  std::vector<A64Result> results;

  A64InstructionException exception = None;

  // Decoding
  void decodeA64(uint32_t encoding);
  void nyi();
  void unallocated();
  void decodeA64DataImmediate(uint32_t insn);
  void decodeA64BranchSystem(uint32_t insn);
  void decodeA64LoadStore(uint32_t insn);
  void decodeA64DataRegister(uint32_t insn);
  void decodeA64DataFPSIMD(uint32_t insn);

  void setSourceRegisters(const std::vector<Register> &registers);
  void setDestinationRegisters(const std::vector<Register> &registers);

  // Scheduling
  short operandsPending;

  bool executed = false;

  // Metadata
  bool isStore_ = false;
  bool isLoad_ = false;
  bool isBranch_ = false;

  // Memory
  void setMemoryAddresses(
      const std::vector<std::pair<uint64_t, uint8_t>> &addresses);
  std::vector<std::pair<uint64_t, uint8_t>> memoryAddresses;
  std::vector<RegisterValue> memoryData;

  // Branches
  uint64_t branchAddress;
};

}  // namespace simeng

#endif