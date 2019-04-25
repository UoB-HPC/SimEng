#include "A64Architecture.hh"

#include <cassert>
#include <iomanip>
#include <iostream>

#include "A64InstructionMetadata.hh"

namespace simeng {

std::unordered_map<uint32_t, A64Instruction> A64Architecture::decodeCache;
std::forward_list<A64InstructionMetadata> A64Architecture::metadataCache;

A64Architecture::A64Architecture() {
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &capstoneHandle) != CS_ERR_OK) {
    std::cerr << "Could not create capstone handle" << std::endl;
    exit(1);
  }

  cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
}
A64Architecture::~A64Architecture() { cs_close(&capstoneHandle); }

uint8_t A64Architecture::predecode(const void* ptr, uint8_t bytesAvailable,
                                   uint64_t instructionAddress,
                                   BranchPrediction prediction,
                                   MacroOp& output) const {
  assert(bytesAvailable >= 4 && "Fewer than 4 bytes supplied to A64 decoder");

  // Dereference the instruction pointer to obtain the instruction word
  const uint32_t insn = *static_cast<const uint32_t*>(ptr);
  const uint8_t* encoding = reinterpret_cast<const uint8_t*>(ptr);

  if (!decodeCache.count(insn)) {
    // Generate a fresh decoding, and add to cache
    cs_insn rawInsn;
    cs_detail rawDetail;
    rawInsn.detail = &rawDetail;

    size_t size = 4;
    uint64_t address = 0;

    bool success =
        cs_disasm_iter(capstoneHandle, &encoding, &size, &address, &rawInsn);

    auto metadata = success ? A64InstructionMetadata(rawInsn)
                            : A64InstructionMetadata(encoding);

    // Cache the metadata
    metadataCache.emplace_front(metadata);
    // Create and cache an instruction using the metadata
    decodeCache.insert({insn, metadataCache.front()});
  }

  // Retrieve the cached instruction
  std::shared_ptr<Instruction> uop =
      std::make_shared<A64Instruction>(decodeCache.find(insn)->second);

  uop->setInstructionAddress(instructionAddress);
  uop->setBranchPrediction(prediction);

  // Bundle uop into output macro-op and return
  output.resize(1);
  output[0] = uop;

  return 4;
}

ExceptionResult A64Architecture::handleException(
    const std::shared_ptr<Instruction>& instruction,
    const RegisterFileSet& registerFileSet, const char* memory) const {
  A64Instruction& insn = *static_cast<A64Instruction*>(instruction.get());

  printException(insn);

  A64InstructionException exception = insn.getException();

  if (exception == A64InstructionException::SupervisorCall) {
    uint64_t nextInstructionAddress = insn.getInstructionAddress() + 4;
    // Retrieve syscall ID held in register x8
    auto syscallId =
        registerFileSet.get({A64RegisterType::GENERAL, 8}).get<uint64_t>();
    std::cout << "Syscall ID is " << syscallId << std::endl;

    ProcessStateChange stateChange;
    switch (syscallId) {
      case 174:  // getuid
        stateChange = {{{A64RegisterType::GENERAL, 0}},
                       {static_cast<uint64_t>(0)}};
        break;
      case 175:  // geteuid
        stateChange = {{{A64RegisterType::GENERAL, 0}},
                       {static_cast<uint64_t>(0)}};
        break;
      default:
        std::cout << "Unrecognised syscall" << std::endl;
        return {true, 0, {}};
    }

    std::cout << "Resuming from 0x" << std::hex << nextInstructionAddress
              << std::dec << "\n"
              << std::endl;

    return {false, nextInstructionAddress, stateChange};
  }

  return {true, 0, {}};
}

std::vector<RegisterFileStructure> A64Architecture::getRegisterFileStructures()
    const {
  return {
      {8, 32},   // General purpose
      {16, 32},  // Vector
      {1, 1}     // NZCV
  };
}

ProcessStateChange A64Architecture::getInitialState(
    span<char> processMemory) const {
  ProcessStateChange changes;

  // Set the base of the stack at the top of process memory
  uint64_t stackBase = processMemory.size();

  // Decrement the stack pointer and populate with initial stack state
  // (https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html)

  // TODO: allow defining process arguments
  // Stack pointer must be aligned to a 16-byte interval
  uint64_t stackPointer = stackBase - 32;

  // argc, 0
  changes.memoryAddresses.push_back({stackBase, 8});
  changes.memoryAddressValues.push_back(static_cast<uint64_t>(0));

  // argv null terminator
  changes.memoryAddresses.push_back({stackBase + 8, 8});
  changes.memoryAddressValues.push_back(static_cast<uint64_t>(0));

  // no environment pointers (envp)

  // environment pointers null terminator
  changes.memoryAddresses.push_back({stackBase + 16, 8});
  changes.memoryAddressValues.push_back(static_cast<uint64_t>(0));

  // ELF auxillary data end-of-table
  changes.memoryAddresses.push_back({stackBase + 24, 8});
  changes.memoryAddressValues.push_back(static_cast<uint64_t>(0));

  // Set the stack pointer register
  changes.modifiedRegisters.push_back({A64RegisterType::GENERAL, 31});
  changes.modifiedRegisterValues.push_back(stackPointer);

  return changes;
}

bool A64Architecture::canRename(Register reg) const { return true; }

void A64Architecture::printException(const A64Instruction& insn) const {
  auto exception = insn.getException();
  std::cout << "Encountered ";
  switch (exception) {
    case A64InstructionException::EncodingUnallocated:
      std::cout << "illegal instruction";
      break;
    case A64InstructionException::ExecutionNotYetImplemented:
      std::cout << "execution not-yet-implemented";
      break;
    case A64InstructionException::SupervisorCall:
      std::cout << "supervisor call";
      break;
    case A64InstructionException::HypervisorCall:
      std::cout << "hypervisor call";
      break;
    case A64InstructionException::SecureMonitorCall:
      std::cout << "secure monitor call";
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
  if (exception == A64InstructionException::EncodingUnallocated) {
    std::cout << "<unknown>";
  } else {
    std::cout << metadata.mnemonic << " " << metadata.operandStr;
  }
  std::cout << "\n      opcode ID: " << metadata.opcode;
  std::cout << std::endl;
}

}  // namespace simeng
