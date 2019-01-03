#include "registerValue.hh"

#include <cstring>

namespace simeng {

RegisterValue::RegisterValue() {
    ptr = std::make_shared<uint8_t>(0);
}
RegisterValue::RegisterValue(std::shared_ptr<uint8_t> ptr) : ptr(ptr) {}

RegisterValue RegisterValue::zeroExtend(uint8_t fromBytes, uint8_t toBytes) const {
    auto extended = RegisterValue(0, toBytes);
    std::memcpy(extended.ptr.get(), ptr.get(), fromBytes);
    return extended;
}

}
