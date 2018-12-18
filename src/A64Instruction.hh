#ifndef __H_A64_INSTRUCTION
#define __H_A64_INSTRUCTION

#include "instruction.hh"

namespace simeng {

typedef struct {
    uint8_t sf;
    uint8_t N;
    uint64_t imm;
} A64DecodeMetadata;

enum A64InstructionException {
    None = 0,
    EncodingUnallocated,
    EncodingNotYetImplemented,
    ExecutionNotYetImplemented
};

enum A64Opcode {
    ORR_I
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
        static std::vector<std::shared_ptr<Instruction>> decode(void* encoding);

        A64Instruction(void* encoding);
        ~A64Instruction() {};

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


        const static int ZERO_REGISTER = -1;

    private:
        A64Opcode opcode;
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
};

}

#endif