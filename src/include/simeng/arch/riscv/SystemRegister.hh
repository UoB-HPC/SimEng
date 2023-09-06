#pragma once

#include <forward_list>
#include <unordered_map>
#include <fstream>
#include <iomanip>

#include "simeng/arch/Architecture.hh"

#include "simeng/arch/riscv/Instruction.hh"
#include "simeng/kernel/Linux.hh"

namespace simeng {
namespace arch {
namespace riscv {

// Should probably move to Capstone

enum riscv_sysreg {
  SYSREG_MSTATUS    = 0x300,
  SYSREG_MIE        = 0x304,
  SYSREG_MTVEC      = 0x305,
  SYSREG_MSTATUSH   = 0x310,
  SYSREG_MSCRATCH   = 0x340,
  SYSREG_MEPC       = 0x341,
  SYSREG_MCAUSE     = 0x342,
  SYSREG_MHARTID    = 0xF14,
  SYSREG_MXCPTSC    = 0xFC2,
  SYSREG_CYCLE      = 0xC00,
  SYSREG_TIME       = 0xC01,
  SYSREG_INSTRRET   = 0xC02
};

enum riscv_causecode_enum {
  CAUSE_IADDRESS_MISALIGN   = 0,
  CAUSE_IACCESS_FAULT       = 1,
  CAUSE_ILLEGAL_INSTRUCTION = 2,
  CAUSE_BREAKPOINT          = 3,
  CAUSE_LDADDRESS_MISALIGN  = 4,
  CAUSE_LDACCESS_FAULT      = 5,
  CAUSE_STADDRESS_MISALIGN  = 6,
  CAUSE_STACCESS_FAULT      = 7,
  CAUSE_ECALL_FROM_M        = 11
};

enum class InterruptId {
  HALT             = 1,
  TIMER            = 7
};

enum riscv_sysreg_masks {
  MSTATUS_MIE_MASK           = 0x8,
  MSTATUS_MPIE_MASK          = 0x80
};

typedef uint16_t riscv_causecode;

class MemoryMappedSystemRegister {
  public:
    MemoryMappedSystemRegister(const RegisterValue& val)          : state(val) {}                
    bool size()                                                   { return state.size(); }
    virtual void  put(const RegisterValue& val)                   { state = val; }
    virtual const RegisterValue& get()                            { return state; }
  private:
    RegisterValue state;
};

class MemoryMappedSystemRegisterBlock {
  public:
    MemoryMappedSystemRegisterBlock(size_t sz)                    : size_(sz) {}
    size_t size()                                                 { return size_; }
    virtual bool put(uint16_t, const RegisterValue&);
    virtual bool get(uint16_t, RegisterValue&);
    virtual void tick()                                           {}
  protected:
    /** Ordered map of memory mapped system regsiters **/
    std::map<uint16_t, MemoryMappedSystemRegister*> memoryMappedSystemRegisters;
    size_t size_;
};

class SystemRegisterMemoryInterface : public MemoryInterface {
  public:
    SystemRegisterMemoryInterface(
      std::shared_ptr<simeng::MemoryInterface>& dataMemory, 
      std::map<uint64_t,MemoryMappedSystemRegisterBlock*>& memoryMappedSystemRegisterBlocks
    ) :
      dataMemory_(dataMemory),
      memoryMappedSystemRegisterBlocks_(memoryMappedSystemRegisterBlocks)
    {}

    /** Request a read from the supplied target location. */
    virtual void requestRead(const MemoryAccessTarget& target,
                            uint64_t requestId = 0)
    {
      RegisterValue data(0,target.size);
      if (getMemoryMappedSystemRegister(target.address, data))
        completedReads_.push_back({target, data, requestId});
      else 
        dataMemory_.get()->requestRead(target,requestId);
    }

    /** Request a write of `data` to the target location. */
    virtual void requestWrite(const MemoryAccessTarget& target,
                              const RegisterValue& data)
    {
      if (!putMemoryMappedSystemRegister(target.address, data))
        dataMemory_.get()->requestWrite(target,data);
    }

    /** Retrieve all completed read requests. */
    virtual const span<MemoryReadResult> getCompletedReads() const
    {
      if (completedReads_.empty())
        return dataMemory_.get()->getCompletedReads();
      else
        return {const_cast<MemoryReadResult*>(completedReads_.data()), completedReads_.size()};
    }

    /** Clear the completed reads. */
    virtual void clearCompletedReads()
    {
      if (completedReads_.empty())
        dataMemory_.get()->clearCompletedReads();
      else 
        completedReads_.clear();
    }

    /** Returns true if there are any oustanding memory requests in-flight. */
    virtual bool hasPendingRequests() const
    {
      return dataMemory_.get()->hasPendingRequests();
    }

    /** Tick the memory interface to allow it to process internal tasks.
    *
    * TODO: Move ticking out of the memory interface and into a central "memory
    * system" covering a set of related interfaces.
    */
    virtual void tick()
    {
      dataMemory_.get()->tick();
    }

  private :
    /** Put/Get Memory Mapped Registers */
    bool putMemoryMappedSystemRegister(uint64_t address, const RegisterValue& value);
    bool getMemoryMappedSystemRegister(uint64_t address, RegisterValue& value);

    std::shared_ptr<simeng::MemoryInterface> dataMemory_;

    /** Address map of all system register blocks */
    std::map<uint64_t,MemoryMappedSystemRegisterBlock*>& memoryMappedSystemRegisterBlocks_;
    
    /** A vector containing all completed read requests. */
    std::vector<MemoryReadResult> completedReads_;
};

class Architecture;

class HostTargetInterface : public MemoryMappedSystemRegisterBlock {
  public:
    enum { 
      PAYLOAD_OFFSET  = 0,
      DEVICEID_OFFSET = 4
    };

    HostTargetInterface(Architecture& architecture)
    : 
      MemoryMappedSystemRegisterBlock(8),
      architecture_(architecture),
      isHalted_(false)
    {
      memoryMappedSystemRegisters[PAYLOAD_OFFSET]  = new MemoryMappedSystemRegister(static_cast<uint32_t>(0));
      memoryMappedSystemRegisters[DEVICEID_OFFSET] = new MemoryMappedSystemRegister(static_cast<uint32_t>(0));
    }

    bool put(uint16_t offset, const RegisterValue&value);

    int16_t updateSystemTimerRegisters(RegisterFileSet* regFile, const uint64_t iterations) {
      if (isHalted_)
        return static_cast<int16_t>(InterruptId::HALT);
      return -1;
    }

  private :
    Architecture& architecture_;
    bool          isHalted_;
};

class Clint : public MemoryMappedSystemRegisterBlock {
  public:
    enum {
      CLINT_BASE        = 0x02000000,
      CLINT_SIZE        = 0x0000c000,
      MTIMECMP_OFFSET   = 0x4000,
      MTIME_OFFSET      = 0xbff8
    };

    Clint(Architecture& architecture)
    :
      MemoryMappedSystemRegisterBlock(CLINT_SIZE),
      architecture_(architecture),
      mtime_(static_cast<uint64_t>(0)),
      mtimecmp_(static_cast<uint64_t>(0)),
      mtime_freq(100),
      mtime_count(0),
      last_tick(0)
    {
      memoryMappedSystemRegisters[MTIME_OFFSET]    = &mtime_;
      memoryMappedSystemRegisters[MTIMECMP_OFFSET] = &mtimecmp_;
    }

    int16_t updateSystemTimerRegisters(RegisterFileSet* regFile, const uint64_t iterations);

  private :
    Architecture& architecture_;

    MemoryMappedSystemRegister mtime_;
    MemoryMappedSystemRegister mtimecmp_;

    uint32_t      mtime_freq;
    uint32_t      mtime_count;
    uint64_t      last_tick;
};


}  // namespace riscv
}  // namespace arch
}  // namespace simeng
