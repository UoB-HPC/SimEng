#ifndef __H_A64_INSTRUCTION
#define __H_A64_INSTRUCTION

#include "instruction.hh"

namespace simeng {

namespace A64RegisterType {
    const uint8_t GENERAL = 0;
    const uint8_t VECTOR = 1;
    const uint8_t NZCV = 2;
}

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
} A64DecodeMetadata;

enum A64InstructionException {
    None = 0,
    EncodingUnallocated,
    EncodingNotYetImplemented,
    ExecutionNotYetImplemented
};

enum class A64Opcode {
    B,
    LDR_I,
    ORR_I,
    STR_I
};


typedef struct {
    RegisterValue value;
    bool ready;
} A64Operand;
typedef struct {
    RegisterValue value;
} A64Result;

class A64Instruction: public Instruction {
    public:
        static std::vector<std::shared_ptr<Instruction>> decode(void* encoding, uint64_t instructionAddress);

        A64Instruction(void* encoding, uint64_t instructionAddress);
        // ~A64Instruction() {};

        InstructionException getException() override;

        std::vector<Register> getOperandRegisters() override;
        std::vector<Register> getDestinationRegisters() override;

        bool isOperandReady(int index) override;

        void rename(const std::vector<Register> &destinations, const std::vector<Register> &operands) override;

        void supplyOperand(Register reg, const RegisterValue &value) override;
        bool canExecute() override;

        void execute() override;
        bool canCommit() override;

        std::vector<RegisterValue> getResults() override;

        std::vector<std::pair<uint64_t, uint8_t>> generateAddresses() override;
        std::vector<std::pair<uint64_t, uint8_t>> getGeneratedAddresses() override;

        void supplyData(uint64_t address, RegisterValue data) override;
        std::vector<RegisterValue> getData() override;

        bool wasBranchMispredicted() override;
        uint64_t getBranchAddress() override;

        bool isStore() override;
        bool isLoad() override;
        bool isBranch() override;

        static const Register ZERO_REGISTER;

    private:
        A64Opcode opcode;
        uint64_t instructionAddress;
        A64DecodeMetadata metadata;

        std::vector<Register> sourceRegisters;
        std::vector<Register> destinationRegisters;

        std::vector<A64Operand> operands;
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

        void setSourceRegisters(std::vector<Register> registers);
        void setDestinationRegisters(std::vector<Register> registers);

        // Scheduling
        short operandsPending;

        bool executed = false;

        // Metadata
        bool isStore_ = false;
        bool isLoad_ = false;
        bool isBranch_ = false;

        // Memory
        void setMemoryAddresses(const std::vector<std::pair<uint64_t, uint8_t>> &addresses);
        std::vector<std::pair<uint64_t, uint8_t>> memoryAddresses;
        std::vector<RegisterValue> memoryData;

        // Branches
        uint64_t branchAddress;
};

}

#endif