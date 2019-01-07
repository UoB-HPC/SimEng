#include "registerFile.hh"


namespace simeng {

std::ostream &operator<<(std::ostream &os, Register const &reg) {
    return os << reg.tag;
}

bool Register::operator==(Register other) {
    return (other.type == type && other.tag == tag);
}

RegisterFile::RegisterFile(int registerCount) {
    registers = std::vector<RegisterValue>(registerCount);

    for (auto i = 0; i < registerCount; i++) {
        registers[i] = RegisterValue(0, 8);
    }
}

RegisterValue RegisterFile::get(Register reg) {
    return registers[reg.tag];
}

void RegisterFile::set(Register reg, const RegisterValue &value) {
    registers[reg.tag] = value;
}

}
