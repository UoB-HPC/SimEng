#ifndef __H_REGISTER_FILE
#define __H_REGISTER_FILE

#include "registerValue.hh"

#include <vector>

typedef short Register;

class RegisterFile {
    public:
        /** Initialise a RegisterFile with `registerCount` registers. */
        RegisterFile(int registerCount);

        /** Read the value of the specified register. */
        RegisterValue get(Register reg);

        /** Set a register as the specified value. */
        void set(Register reg, RegisterValue value);
    private:
        std::vector<RegisterValue> registers;
};

#endif