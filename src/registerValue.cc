#include "registerValue.hh"

namespace simeng {

RegisterValue::RegisterValue() {
    ptr = std::make_shared<uint8_t>(0);
}
RegisterValue::RegisterValue(std::shared_ptr<uint8_t> ptr) : ptr(ptr) {}

}
