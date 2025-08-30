#pragma once

#include <memory>
#include <string>

#include "simeng/Accelerator.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/config/AcceleratorInfo.hh"
#include "simeng/config/AcceleratorType.hh"
#include "simeng/kernel/Linux.hh"
#include "simeng/memory/MemoryInterface.hh"
#include "simeng/pipeline/PortAllocator.hh"

namespace simeng {

/** A class for creating a SimEng Accelerator instance from a config at supplied
 * path. */
class AcceleratorInstance {
 public:
  explicit AcceleratorInstance(const std::string& configPath,
                               Accelerator::gateway_t::send_fn_t sendFn,
                               Accelerator::gateway_t::receive_fn_t recvFn);

  /** Set the SimEng L1 data cache memory. Note that it has to be a different
   * instance from the one provided to the core. */
  void setL1DataMemory(std::shared_ptr<memory::MemoryInterface> memRef);

  /** Construct the core and all its associated simulation objects after the
   * memory interface has been instantiated. */
  void createAccelerator();

  /** Returns the constructed accelerator instance. */
  std::shared_ptr<Accelerator> getAccelerator() const;

  /** Getter for the data memory object. */
  std::shared_ptr<memory::MemoryInterface> getDataMemory() const;

  /** Getter for AcceleratorInfo object. */
  const config::AcceleratorInfo& getAcceleratorInfo() const;

  /** Getter for the architecture object. */
  const arch::Architecture& getArch() const;

  /** Maps the provided accelerator names to their IDs. */
  static std::vector<config::AcceleratorType> getAcceleratorTypesFromNames(
      const std::vector<std::string>& names);

  /** Returns a isReady VTable for the given list of accelerators. */
  static config::OffloadingLogic::is_ready_vtable_t getIsReadyVTable(
      const std::vector<config::AcceleratorType>& accelerators);

  /** Returns a register filter VTable for the given list of accelerators. */
  static config::OffloadingLogic::register_filter_vtable_t
  getRegisterFilterVTable(
      const std::vector<config::AcceleratorType>& accelerators);

 private:
  /** Generate the appropriate simulation objects as parameterised by the
   * configuration.*/
  void generateAcceleratorModel();

  /** An object describing the modelled accelerator to be created. */
  std::shared_ptr<config::AcceleratorInfo> info_;

  /** The function for sending packets over the NoC. It takes a reference
   * to the packet and returns whether it has been successfully sent. */
  Accelerator::gateway_t::send_fn_t sendFn_;

  /** The function for receiving packets from the NoC. Returns the latest packet
   * received from the network, if there are any. */
  Accelerator::gateway_t::receive_fn_t recvFn_;

  /** Whether the dataMemory_ must be set manually. */
  bool setMemory_ = false;

  /** The SimEng Linux kernel object. */
  kernel::Linux kernel_;

  /** SimEng architecture object. */
  std::unique_ptr<arch::Architecture> arch_ = nullptr;

  /** SimEng port allocator object. */
  std::unique_ptr<pipeline::PortAllocator> portAllocator_ = nullptr;

  /** SimEng accelerator object. */
  std::shared_ptr<Accelerator> accelerator_ = nullptr;

  /** Pointer to the SimEng data memory object. */
  std::shared_ptr<memory::MemoryInterface> dataMemory_ = nullptr;
};

}  // namespace simeng
