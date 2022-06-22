#include "simeng/arch/aarch64/AArch64ExceptionHandler.hh"

#include <iomanip>
#include <iostream>

#include "InstructionMetadata.hh"
#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/arch/aarch64/Instruction.hh"

namespace simeng {
namespace arch {

aarch64::AArch64ExceptionHandler::AArch64ExceptionHandler(
    const std::shared_ptr<simeng::Instruction>& instruction, const Core& core,
    MemoryInterface& memory, kernel::Linux& linux)
    : GenericExceptionHandler(core, memory, linux),
      instruction_(*static_cast<Instruction*>(instruction.get())) {}

uint64_t aarch64::AArch64ExceptionHandler::callNumberConversionToAArch64(
    uint64_t syscallNumber) const {
  // No conversion necessary
  return syscallNumber;
}

uint64_t aarch64::AArch64ExceptionHandler::getSyscallID() const {
  const auto& registerFileSet = core.getArchitecturalRegisterFileSet();
  return registerFileSet.get({RegisterType::GENERAL, 8}).get<uint64_t>();
}

bool aarch64::AArch64ExceptionHandler::isSupervisorCall() const {
  return instruction_.getException() == InstructionException::SupervisorCall;
}

Register aarch64::AArch64ExceptionHandler::getSupervisorCallRegister(
    int regNumber) const {
  switch (regNumber) {
    case 0:
      return {RegisterType::GENERAL, 0};
    case 1:
      return {RegisterType::GENERAL, 1};
    case 2:
      return {RegisterType::GENERAL, 2};
    case 3:
      return {RegisterType::GENERAL, 3};
    case 4:
      return {RegisterType::GENERAL, 4};
    case 5:
      return {RegisterType::GENERAL, 5};
    default:
      assert(true && "Supervisor call register out of range");
  }
}

void aarch64::AArch64ExceptionHandler::printException() const {
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

uint64_t aarch64::AArch64ExceptionHandler::getInstructionSequenceID() const {
  return instruction_.getSequenceId();
}

uint64_t aarch64::AArch64ExceptionHandler::getInstructionAddress() const {
  return instruction_.getInstructionAddress();
}
ProcessStateChange aarch64::AArch64ExceptionHandler::uname(uint64_t base,
                                                           Register R0) const {
  const uint8_t len = 65;  // Reserved length of each string field in Linux
  const char sysname[] = "Linux";
  const char nodename[] = "simeng.hpc.cs.bris.ac.uk";
  const char release[] = "4.14.0";
  const char version[] = "#1 SimEng Mon Apr 29 16:28:37 UTC 2019";
  const char machine[] = "aarch64";

  return {
      ChangeType::REPLACEMENT,
      {R0},
      {0ull},
      {{base, sizeof(sysname)},
       {base + len, sizeof(nodename)},
       {base + (len * 2), sizeof(release)},
       {base + (len * 3), sizeof(version)},
       {base + (len * 4), sizeof(machine)}},
      {RegisterValue(sysname), RegisterValue(nodename), RegisterValue(release),
       RegisterValue(version), RegisterValue(machine)}};
}

}  // namespace arch
}  // namespace simeng