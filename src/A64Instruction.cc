#include "A64Instruction.hh"

#include <vector>
#include <algorithm>
#include <iostream>

namespace simeng {

std::vector<std::shared_ptr<Instruction>> A64Instruction::decode(void* test) {
    auto uop = std::make_shared<A64Instruction>(A64Instruction(test));
    std::vector<std::shared_ptr<Instruction>> macroOp{ uop };
    return macroOp;
}

A64Instruction::A64Instruction(void* encoding) {
    uint32_t insn = *((uint32_t*) encoding);
    decodeA64(insn);
}

InstructionException A64Instruction::getException() {
    return exception;
}

void A64Instruction::setSourceRegisters(std::vector<Register> registers) {
    operands = std::vector<A64Operand>(registers.size());
    operandsPending = registers.size();

    for (auto i = 0; i < registers.size(); i++) {
        auto reg = registers[i];
        if (reg == ZERO_REGISTER) {
            // Any zero-register references should be marked as ready, and
            //  the corresponding operand value zeroed
            operands[i].value = RegisterValue(0, 8);
            operands[i].ready = true;
            operandsPending--;
        }
    }
    sourceRegisters = registers;
}
void A64Instruction::setDestinationRegisters(std::vector<Register> registers) {
    destinationRegisters = registers;
    results = std::vector<A64Result>(destinationRegisters.size());
}

std::vector<Register> A64Instruction::getOperandRegisters() {
    return sourceRegisters;
}
std::vector<Register> A64Instruction::getDestinationRegisters() {
    return destinationRegisters;
}
bool A64Instruction::isOperandReady(int index) {
    return operands[index].ready;
}

void A64Instruction::rename(const std::vector<Register> &destinations, const std::vector<Register> &operands) {
    destinationRegisters = destinations;
    sourceRegisters = operands;
}

void A64Instruction::supplyOperand(Register reg, const RegisterValue &value) {
    if (canExecute()) {
        return;
    }

    for (auto i = 0; i < sourceRegisters.size(); i++) {
        if (sourceRegisters[i] == reg) {
            if (!operands[i].ready) {
                operands[i].value = value;
                operands[i].ready = true;
                operandsPending--;
            }
            break;
        }
    }
}

bool A64Instruction::canExecute() {
    return (operandsPending == 0);
}

bool A64Instruction::canCommit() {
    return executed;
}

std::vector<RegisterValue> A64Instruction::getResults() {
    auto out = std::vector<RegisterValue>(results.size());
    std::transform(results.begin(), results.end(), out.begin(), [](A64Result item) { return item.value; });
    return out;
}

}
