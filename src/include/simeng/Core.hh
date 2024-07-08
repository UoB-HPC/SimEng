#pragma once

#include <iostream>
#include <map>
#include <string>

#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/arch/ProcessStateChange.hh"
#include "simeng/config/SimInfo.hh"
#include "simeng/memory/MemoryInterface.hh"

namespace simeng {

namespace arch {
// Forward declare Architecture and ExceptionHandler classes.
class Architecture;
class ExceptionHandler;
}  // namespace arch

/** An abstract core model. */
class Core {
 public:
  Core(memory::MemoryInterface& dataMemory, const arch::Architecture& isa,
       const std::vector<RegisterFileStructure>& regFileStructure)
      : dataMemory_(dataMemory),
        isa_(isa),
        registerFileSet_(regFileStructure),
        clockFrequency_(
            config::SimInfo::getConfig()["Core"]["Clock-Frequency-GHz"]
                .as<float>()) {}

  virtual ~Core() {}

  /** Tick the core. */
  virtual void tick() = 0;

  /** Check whether the program has halted. */
  virtual bool hasHalted() const = 0;

  /** Retrieve the architectural register file set. */
  virtual const ArchitecturalRegisterFileSet& getArchitecturalRegisterFileSet()
      const = 0;

  /** Retrieve the number of instructions retired. */
  virtual uint64_t getInstructionsRetiredCount() const = 0;

  /** Retrieve a map of statistics to report. */
  virtual std::map<std::string, std::string> getStats() const = 0;

  /** Retrieve the simulated nanoseconds elapsed since the core started. */
  uint64_t getSystemTimer() const {
    // TODO: This will need to be changed if we start supporting DVFS.
    return (ticks_ / clockFrequency_);
  }

 protected:
  /** Apply changes to the process state. */
  void applyStateChange(const arch::ProcessStateChange& change) const {
    auto& regFile = const_cast<ArchitecturalRegisterFileSet&>(
        getArchitecturalRegisterFileSet());
    // Update registers in accordance with the ProcessStateChange type
    switch (change.type) {
      case arch::ChangeType::INCREMENT: {
        for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
          regFile.set(change.modifiedRegisters[i],
                      regFile.get(change.modifiedRegisters[i]).get<uint64_t>() +
                          change.modifiedRegisterValues[i].get<uint64_t>());
        }
        break;
      }
      case arch::ChangeType::DECREMENT: {
        for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
          regFile.set(change.modifiedRegisters[i],
                      regFile.get(change.modifiedRegisters[i]).get<uint64_t>() -
                          change.modifiedRegisterValues[i].get<uint64_t>());
        }
        break;
      }
      default: {  // arch::ChangeType::REPLACEMENT
        // If type is ChangeType::REPLACEMENT, set new values
        for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
          outputFile_ << "\t{" << unsigned(change.modifiedRegisters[i].type)
                      << ":" << change.modifiedRegisters[i].tag << "}"
                      << " <- " << std::hex;
          for (int j = change.modifiedRegisterValues[i].size() - 1; j >= 0;
               j--) {
            if (change.modifiedRegisterValues[i].getAsVector<uint8_t>()[j] < 16)
              outputFile_ << "0";
            outputFile_ << unsigned(
                change.modifiedRegisterValues[i].getAsVector<uint8_t>()[j]);
          }
          outputFile_ << std::dec << std::endl;
          regFile.set(change.modifiedRegisters[i],
                      change.modifiedRegisterValues[i]);
        }
        break;
      }
    }

    // Update memory
    // TODO: Analyse if ChangeType::INCREMENT or ChangeType::DECREMENT case is
    // required for memory changes
    for (size_t i = 0; i < change.memoryAddresses.size(); i++) {
      outputFile_ << "\tAddr " << std::hex << change.memoryAddresses[i].address
                  << std::dec << " <- " << std::hex;
      for (int j = change.memoryAddressValues[i].size() - 1; j >= 0; j--) {
        if (change.memoryAddressValues[i].getAsVector<uint8_t>()[j] < 16)
          outputFile_ << "0";
        outputFile_ << unsigned(
            change.memoryAddressValues[i].getAsVector<uint8_t>()[j]);
      }
      outputFile_ << std::dec << std::endl;
      dataMemory_.requestWrite(change.memoryAddresses[i],
                               change.memoryAddressValues[i]);
    }
  }

  /** A memory interface to access data. */
  memory::MemoryInterface& dataMemory_;

  /** The currently used ISA. */
  const arch::Architecture& isa_;

  /** The core's register file set. */
  RegisterFileSet registerFileSet_;

  /** The active exception handler. */
  std::shared_ptr<arch::ExceptionHandler> exceptionHandler_;

  /** The number of times this core has been ticked. */
  uint64_t ticks_ = 0;

  /** Whether or not the core has halted. */
  bool hasHalted_ = false;

  /** Clock frequency of core in GHz */
  float clockFrequency_ = 0.0f;

  mutable std::ofstream outputFile_;
};

}  // namespace simeng
