#ifndef __H_REGISTER_FILE
#define __H_REGISTER_FILE

#include "registerValue.hh"

#include <vector>

namespace simeng {

struct Register {
  uint8_t type;
  uint16_t tag;

  bool operator==(Register other);
};
std::ostream &operator<<(std::ostream &os, simeng::Register const &reg);

class RegisterFile {
 public:
  /** Initialise multiple register groups. Each entry in `registerFileSizes`
   * states the number of registers that should be available for the register
   * type corresponding to the entry's index. */
  RegisterFile(std::vector<uint16_t> registerFileSizes);

  /** Read the value of the specified register. */
  RegisterValue get(Register reg);

  /** Set a register as the specified value. */
  void set(Register reg, const RegisterValue &value);

 private:
  std::vector<std::vector<RegisterValue>> registerFiles;
};

}  // namespace simeng

#endif
