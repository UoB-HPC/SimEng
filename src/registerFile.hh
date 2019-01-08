#ifndef __H_REGISTER_FILE
#define __H_REGISTER_FILE

#include "registerValue.hh"

#include <vector>

namespace simeng {

// typedef short Register;
struct Register {
    uint8_t type;
    uint16_t tag;

    bool operator==(Register other);
};
std::ostream &operator<<(std::ostream &os, simeng::Register const &reg);

class RegisterFile {
    public:
        /** Initialise a RegisterFile with `registerCount` registers. */
        RegisterFile(std::vector<uint16_t> registerFileSizes);

        /** Read the value of the specified register. */
        RegisterValue get(Register reg);

        /** Set a register as the specified value. */
        void set(Register reg, const RegisterValue &value);
    private:
        std::vector<std::vector<RegisterValue>> registerFiles;
};

}

#endif
