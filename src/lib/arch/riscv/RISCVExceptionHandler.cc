#include "simeng/arch/riscv/RISCVExceptionHandler.hh"

#include <iomanip>
#include <iostream>

#include "InstructionMetadata.hh"
#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/arch/riscv/Instruction.hh"

namespace simeng {
namespace arch {

riscv::RISCVExceptionHandler::RISCVExceptionHandler(
    const std::shared_ptr<simeng::Instruction>& instruction, const Core& core,
    MemoryInterface& memory, kernel::Linux& linux)
    : GenericExceptionHandler(core, memory, linux),
      instruction_(*static_cast<Instruction*>(instruction.get())) {}

uint64_t riscv::RISCVExceptionHandler::convertToSEReprisentation(
    uint64_t syscallNumber) const {
  // No conversion necessary
  return syscallNumber;
}

bool riscv::RISCVExceptionHandler::isSupervisorCall() const {
  return instruction_.getException() == InstructionException::SupervisorCall;
}

Register riscv::RISCVExceptionHandler::getSupervisorCallRegister(
    int regNumber) const {
  switch (regNumber) {
    case -1:
      return {RegisterType::GENERAL, 17};
    case 0:
      return {RegisterType::GENERAL, 10};
    case 1:
      return {RegisterType::GENERAL, 11};
    case 2:
      return {RegisterType::GENERAL, 12};
    case 3:
      return {RegisterType::GENERAL, 13};
    case 4:
      return {RegisterType::GENERAL, 14};
    case 5:
      return {RegisterType::GENERAL, 15};
    default:
      assert(false && "Supervisor call register out of range");
  }
}

void riscv::RISCVExceptionHandler::printException() const {
  auto insn = instruction_;
  auto exception = insn.getException();
  std::cout << std::endl;
  std::cout << "Encountered ";
  switch (exception) {
    case InstructionException::EncodingUnallocated:
      std::cout << "illegal instruction";
      break;
    case InstructionException::ExecutionNotYetImplemented:
      std::cout << "execution not-yet-implemented";
      break;
    case InstructionException::MisalignedPC:
      std::cout << "misaligned program counter";
      break;
    case InstructionException::DataAbort:
      std::cout << "data abort";
      break;
    case InstructionException::SupervisorCall:
      std::cout << "supervisor call";
      break;
    case InstructionException::HypervisorCall:
      std::cout << "hypervisor call";
      break;
    case InstructionException::SecureMonitorCall:
      std::cout << "secure monitor call";
      break;
    case InstructionException::NoAvailablePort:
      std::cout << "unsupported execution port";
      break;
    default:
      std::cout << "unknown (id: " << static_cast<unsigned int>(exception)
                << ")";
  }
  std::cout << " exception\n";

  std::cout << "  Generated by instruction: \n"
            << "    0x" << std::hex << std::setfill('0') << std::setw(16)
            << insn.getInstructionAddress() << ": ";

  auto& metadata = insn.getMetadata();
  for (uint8_t byte : metadata.encoding) {
    std::cout << std::setfill('0') << std::setw(2)
              << static_cast<unsigned int>(byte) << " ";
  }
  std::cout << std::dec << "    ";
  if (exception == InstructionException::EncodingUnallocated) {
    std::cout << "<unknown>";
  } else {
    std::cout << metadata.mnemonic << " " << metadata.operandStr;
  }
  std::cout << "\n      opcode ID: " << metadata.opcode;
  std::cout << std::endl;
}

uint64_t riscv::RISCVExceptionHandler::getInstructionSequenceID() const {
  return instruction_.getSequenceId();
}

uint64_t riscv::RISCVExceptionHandler::getInstructionAddress() const {
  return instruction_.getInstructionAddress();
}

ProcessStateChange riscv::RISCVExceptionHandler::uname(uint64_t base,
                                                       Register R0) const {
  const uint8_t len = 65;  // Reserved length of each string field in Linux
  const char sysname[] = "Linux";
  const char nodename[] = "fedora-riscv";
  const char release[] = "5.5.0-0.rc5.git0.1.1.riscv64.fc32.riscv64";
  const char version[] = "#1 SMP Mon Jan 6 17:31:22 UTC 2020";
  const char machine[] = "riscv64";
  const char domainname[] = "(none)";

  return {ChangeType::REPLACEMENT,
          {R0},
          {0ull},
          {{base, sizeof(sysname)},
           {base + len, sizeof(nodename)},
           {base + (len * 2), sizeof(release)},
           {base + (len * 3), sizeof(version)},
           {base + (len * 4), sizeof(machine)},
           {base + (len * 5), sizeof(domainname)}},
          {RegisterValue(sysname), RegisterValue(nodename),
           RegisterValue(release), RegisterValue(version),
           RegisterValue(machine), RegisterValue(domainname)}};
}

}  // namespace arch
}  // namespace simeng