#ifndef __H_INSTRUCTION
#define __H_INSTRUCTION

#include "registerValue.hh"
#include "registerFile.hh"

#include <vector>

typedef short InstructionException;

namespace simeng {

/** An abstract instruction definition.
 * Each supported ISA should provide an derived implementation of this class. */
class Instruction {
    public:
        virtual ~Instruction() {};

        /** Retrieve the identifier for the first exception that occurred during decoding or execution. */
        virtual InstructionException getException() = 0;

        /** Retrieve a vector of source registers this instruction reads. */
        virtual std::vector<Register> getOperandRegisters() = 0;

        /** Retrieve a vector of destination registers this instruction will write to.
         * A register value of -1 signifies a Zero Register read, and should not be renamed. */
        virtual std::vector<Register> getDestinationRegisters() = 0;

        /** Override the destination and operand registers with renamed physical register tags. */
        virtual void rename(const std::vector<Register> &destinations, const std::vector<Register> &operands) = 0;

        /** Provide a value for the specified physical register. */
        virtual void supplyOperand(Register reg, const RegisterValue &value) = 0;

        /** Check whether the operand at index `i` has had a value supplied. */
        virtual bool isOperandReady(int i) = 0;

        /** Check whether all operand values have been supplied, and the instruction is ready to execute. */
        virtual bool canExecute() = 0;

        /** Execute the instruction. */
        virtual void execute() = 0;

        /** Check whether the instruction has executed and has results ready to commit. */
        virtual bool canCommit() = 0;

        /** Retrieve the results to commit. */
        virtual std::vector<RegisterValue> getResults() = 0;
};

}

#endif