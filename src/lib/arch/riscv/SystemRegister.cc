#include "simeng/arch/riscv/Architecture.hh"

namespace simeng {
namespace arch {
namespace riscv {

bool MemoryMappedSystemRegisterBlock::put(uint16_t offset, const RegisterValue& value)
{
  auto it = memoryMappedSystemRegisters.upper_bound(offset);
  if  (it != memoryMappedSystemRegisters.begin() )
  {
    it--;
    if (offset-it->first < it->second->size()) {
      it->second->put(value);
      return true;
    }
    return false;
  }
  return false;
}

bool MemoryMappedSystemRegisterBlock::get(uint16_t offset, RegisterValue& value)
{
  auto it = memoryMappedSystemRegisters.upper_bound(offset);
  if  (it != memoryMappedSystemRegisters.begin() )
  {
    it--;
    if (offset-it->first < it->second->size()) {
      value = it->second->get();
      return true;
    }
    return false;
  }
  return false;
}

/** Put/Get Memory Mapped Registers */
bool SystemRegisterMemoryInterface::putMemoryMappedSystemRegister(uint64_t address, const RegisterValue& value)
{
  auto it = memoryMappedSystemRegisterBlocks_.upper_bound(address);
  if  (it != memoryMappedSystemRegisterBlocks_.begin() )
  {
    it--;
    if (address-it->first < it->second->size()) {
      it->second->put(static_cast<uint16_t>(address-it->first),value);
      return true;
    }
    return false;
  }
  return false;
}

bool SystemRegisterMemoryInterface::getMemoryMappedSystemRegister(uint64_t address, RegisterValue& value)
{
  auto it = memoryMappedSystemRegisterBlocks_.upper_bound(address);
  if  (it != memoryMappedSystemRegisterBlocks_.begin() )
  {
    it--;
    if (address-it->first < it->second->size()) {
      it->second->get(static_cast<uint16_t>(address-it->first),value);
      return true;
    }
    return false;
  }
  return false;
}

bool HostTargetInterface::put(uint16_t offset, const RegisterValue&value)
{
  switch(offset) {
    case PAYLOAD_OFFSET : 
    {
      char ch = value.getAsVector<uint8_t>()[0];
      if (ch==3 || ch==1)
        isHalted_ = true;
      else 
        putchar(ch);
      return true;
    }
    default :
      return MemoryMappedSystemRegisterBlock::put(offset, value);
  }
}

int16_t Clint::updateSystemTimerRegisters(RegisterFileSet* regFile, const uint64_t iterations)
{
  uint64_t ticks      = iterations-last_tick;
  uint64_t mtime_val  = mtime_.get().get<uint64_t>();
  bool     ticked     = false;

  last_tick = iterations;

  // if large time passed then multiple timer ticks might be needed
  while (ticks>=mtime_count)
  {
    ticks       -= mtime_count;
    mtime_count  = mtime_freq;
    mtime_val   += 1;
    ticked       = true;
  }

  // any remaining ticks taken of mtime countdown
  if (ticks)
    mtime_count -= ticks;

  mtime_.put(mtime_val);

  if (ticked)
  {
    // to improve execution speed only do interrupt checks when the timer ticks
    // check if interrupts enabled
    uint16_t mstatus_tag  = static_cast<uint16_t>(architecture_.getSystemRegisterTag(SYSREG_MSTATUS));
    auto     mstatus_bits = regFile->get( { RegisterType::SYSTEM, mstatus_tag } ).get<uint64_t>();
    if (mstatus_bits & MSTATUS_MIE_MASK)
      if  (mtime_val >= mtimecmp_.get().get<uint64_t>())
        return static_cast<uint16_t>(InterruptId::TIMER);
  }

  return -1;
}

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
