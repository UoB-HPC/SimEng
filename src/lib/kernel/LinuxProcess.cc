#include "simeng/kernel/LinuxProcess.hh"

#include <cassert>
#include <cstring>
#include <iostream>

namespace simeng {
namespace kernel {

uint64_t alignToBoundary(uint64_t value, uint64_t boundary) {
  auto remainder = value % boundary;
  if (remainder == 0) {
    return value;
  }

  return value + (boundary - remainder);
}

LinuxProcess::LinuxProcess(const std::vector<std::string>& commandLine,
                           Translator& translator)
    : commandLine_(commandLine), translator_(translator) {
  // Parse ELF file
  assert(commandLine.size() > 0);
  Elf elf(commandLine[0]);
  if (!elf.isValid()) {
    return;
  }
  isValid_ = true;

  // Get notes segement read in by ELF class
  elf.getNotes(noteSegment_);

  auto nt_prstatus = std::find_if(
      noteSegment_.begin(), noteSegment_.end(), [](const NoteEntry entry) {
        return (entry.n_type == 1 &&
                (std::string(entry.name).compare("CORE\0") == 0));
      });

  if (nt_prstatus != noteSegment_.end()) {
    std::cout << "Reading " << nt_prstatus->name << std::endl;
    // If notes segment contains a PC value, use it
    entryPoint_ = *reinterpret_cast<uint64_t*>(nt_prstatus->desc +
                                               (nt_prstatus->n_descsz - 24));
    // If notes segment contains a SP value, use it
    stackPointer_ = *reinterpret_cast<uint64_t*>(nt_prstatus->desc +
                                                 (nt_prstatus->n_descsz - 32));
  } else {
    entryPoint_ = elf.getEntryPoint();
  }

  processMmapStart_ = 0x400000000000;

  // Get ELF headers and their contents
  std::vector<ElfHeader> headerContents;
  elf.getContents(headerContents);
  // First read-in LOAD segments located before the arbitrary mmap region
  for (const auto& header : headerContents) {
    if (header.type == 1 && header.virtualAddress < processMmapStart_) {
      // Add a mapping for this header's contents
      if (!translator_.add_mapping(
              {header.virtualAddress,
               header.virtualAddress + header.memorySize},
              {simulationBrk_, simulationBrk_ + header.memorySize})) {
        isValid_ = false;
        return;
      }
      // Increment the location of the initial program break
      simulationBrk_ += header.memorySize;
      processBrk_ = header.virtualAddress + header.memorySize > processBrk_
                        ? header.virtualAddress + header.memorySize
                        : processBrk_;
    }
  }

  // Add mapping for initial program break
  translator_.add_mapping({processBrk_, processBrk_},
                          {simulationBrk_, simulationBrk_});

  // Set simualtion mmap region start to be an equal distance from the
  // stack and heap starts. Additionally, align to the page size (4kb)
  simulationMmapStart_ = processMmapStart_ =
      alignToBoundary(simulationBrk_ + (HEAP_SIZE + STACK_SIZE) / 2, pageSize_);

  // Update translator with mmap start regions to aid with previous and future
  // mmap calls
  translator_.setInitialBrk(processMmapStart_, simulationMmapStart_);

  // Calculate process image size, including heap + stack
  size_ = simulationBrk_ + HEAP_SIZE + STACK_SIZE;
  processImage_ = new char[size_];

  // Copy all mapped header contents into the processImage_
  uint64_t lastBoundary = 0;
  for (const auto& header : headerContents) {
    if (header.type == 1 && header.virtualAddress < processMmapStart_) {
      std::memcpy(processImage_ + lastBoundary, header.content,
                  header.fileSize);
      lastBoundary += header.memorySize;
    }
  }

  // Next read-in LOAD segments located within the arbitrary mmap region
  lastBoundary = simulationMmapStart_;
  for (const auto& header : headerContents) {
    if (header.type == 1 && header.virtualAddress >= processMmapStart_ &&
        header.virtualAddress < stackPointer_) {
      // Add a mapping for this header's contents
      if (!translator_.add_mapping(
              {header.virtualAddress,
               header.virtualAddress + header.memorySize},
              {lastBoundary, lastBoundary + header.memorySize})) {
        isValid_ = false;
        return;
      }
      // Register mmap allocation that caused this LOAD segment
      translator_.register_allocation(
          header.virtualAddress, header.memorySize,
          {lastBoundary, lastBoundary + header.memorySize});
      // Copy header contents into the newly mapped mmap allocation
      std::memcpy(processImage_ + lastBoundary, header.content,
                  header.fileSize);
      lastBoundary += header.memorySize;
    }
  }

  // Finally read-in the LOAD segment containing the stack
  for (const auto& header : headerContents) {
    if (header.type == 1 && header.virtualAddress >= stackPointer_) {
      // Add a mapping for this header's contents
      if (!translator_.add_mapping(
              {(header.virtualAddress + header.memorySize - STACK_SIZE),
               header.virtualAddress + header.memorySize},
              {(size_ - STACK_SIZE), size_})) {
        isValid_ = false;
        return;
      }
      // Copy header content into simulation stack space and break
      std::memcpy(processImage_ + (size_ - header.fileSize), header.content,
                  header.fileSize);
      break;
    }
  }

  // If the passed in workload had no stack LOAD segment, create one
  if (stackPointer_ == 0) {
    createStack();
    // Add a mapping for the STACK_SIZE allocated
    if (!translator_.add_mapping({size_ - STACK_SIZE, size_},
                                 {size_ - STACK_SIZE, size_})) {
      isValid_ = false;
      return;
    }
  }
}

LinuxProcess::LinuxProcess(span<char> instructions, Translator& translator)
    : translator_(translator) {
  // Leave program command string empty
  commandLine_.push_back("\0");

  isValid_ = true;

  // Align heap start to a 32-byte boundary
  simulationBrk_ = processBrk_ = alignToBoundary(instructions.size(), 32);
  // Add mapping for initial program break
  translator_.add_mapping({processBrk_, processBrk_},
                          {simulationBrk_, simulationBrk_});

  // Set simualtion mmap region start to be an equal distance from the
  // stack and heap starts. Additionally, align to the page size (4kb)
  simulationMmapStart_ = processMmapStart_ =
      alignToBoundary(simulationBrk_ + (HEAP_SIZE + STACK_SIZE) / 2, pageSize_);

  // Update translator with mmap start regions to aid with previous and future
  // mmap calls
  translator_.setInitialBrk(processMmapStart_, simulationMmapStart_);

  // Calculate process image size, including heap + stack
  size_ = simulationBrk_ + HEAP_SIZE + STACK_SIZE;
  processImage_ = new char[size_];
  // Copy in instructions to processImage_
  std::copy(instructions.begin(), instructions.end(), processImage_);
  // Add mapping for instruction region
  if (!translator_.add_mapping({0, processBrk_}, {0, simulationBrk_})) {
    isValid_ = false;
    return;
  }

  createStack();
  // Add a mapping for the STACK_SIZE allocated
  if (!translator_.add_mapping(
          {getStackStart() - STACK_SIZE, getStackStart()},
          {getStackStart() - STACK_SIZE, getStackStart()})) {
    isValid_ = false;
    return;
  }
}

LinuxProcess::~LinuxProcess() {
  if (isValid_) {
    delete[] processImage_;
  }
}

uint64_t LinuxProcess::getProcessBrk() const { return processBrk_; }

uint64_t LinuxProcess::getSimulationBrk() const { return simulationBrk_; }

uint64_t LinuxProcess::getStackStart() const { return size_; }

uint64_t LinuxProcess::getProcessMmapStart() const { return processMmapStart_; }

uint64_t LinuxProcess::getSimulationMmapStart() const {
  return simulationMmapStart_;
}

uint64_t LinuxProcess::getPageSize() const { return pageSize_; }

std::string LinuxProcess::getPath() const { return commandLine_[0]; }

bool LinuxProcess::isValid() const { return isValid_; }

const span<char> LinuxProcess::getProcessImage() const {
  return {processImage_, size_};
}

const NoteEntry LinuxProcess::getNote(uint32_t type) const {
  auto nt_section = std::find_if(
      noteSegment_.begin(), noteSegment_.end(),
      [type](const NoteEntry entry) { return (entry.n_type == type); });
  if (nt_section != noteSegment_.end()) {
    return *nt_section;
  }
  // Return NoteEntry with default values if section not found
  return {0, 0, 0, NULL, NULL};
}

uint64_t LinuxProcess::getEntryPoint() const { return entryPoint_; }

uint64_t LinuxProcess::getStackPointer() const { return stackPointer_; }

void LinuxProcess::createStack() {
  // Decrement the stack pointer and populate with initial stack state
  // (https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html)
  // The argv and env strings are added to the top of the stack first and the
  // lower section of the initial stack is populated from the initialStackFrame
  // vector

  stackPointer_ = getStackStart();
  std::vector<uint64_t> initialStackFrame;
  // Stack strings are split into bytes to easily support the injection of null
  // bytes dictating the end of a string
  std::vector<uint8_t> stringBytes;

  // Program arguments (argc, argv[])
  initialStackFrame.push_back(commandLine_.size());  // argc
  for (size_t i = 0; i < commandLine_.size(); i++) {
    char* argvi = commandLine_[i].data();
    for (int j = 0; j < commandLine_[i].size(); j++) {
      stringBytes.push_back(argvi[j]);
    }
    stringBytes.push_back(0);
  }
  // Environment strings
  std::vector<std::string> envStrings = {"OMP_NUM_THREADS=1"};
  for (std::string& env : envStrings) {
    for (int i = 0; i < env.size(); i++) {
      stringBytes.push_back(env.c_str()[i]);
    }
    // Null entry to seperate strings
    stringBytes.push_back(0);
  }
  // NULL entry at the top of initial stack
  for (int i = 0; i < 8; i++) {
    stringBytes.push_back(1);
  }

  // Store strings and record both argv and environment pointers
  // Block out stack space for strings to be stored in
  stackPointer_ -= alignToBoundary(stringBytes.size() + 1, 32);
  uint16_t ptrCount = 1;
  initialStackFrame.push_back(stackPointer_);  // argv[0] ptr
  uint64_t stringsStart = stackPointer_;
  for (int i = 0; i < stringBytes.size(); i++) {
    if (ptrCount == commandLine_.size()) {
      // null terminator to seperate argv and env strings
      initialStackFrame.push_back(0);
      ptrCount++;
    }
    if (i > 0 && stringBytes[i - 1] == 0x0) {            // i - 1 == null
      initialStackFrame.push_back(stackPointer_ + (i));  // argv/env ptr
      ptrCount++;
    }
    processImage_[stackPointer_ + i] = stringBytes[i];
  }

  initialStackFrame.push_back(0);  // null terminator

  // ELF auxillary vector, keys defined in `uapi/linux/auxvec.h`
  // TODO: populate remaining auxillary vector entries
  initialStackFrame.push_back(6);  // AT_PAGESZ
  initialStackFrame.push_back(pageSize_);
  initialStackFrame.push_back(25);            // AT_RANDOM
  initialStackFrame.push_back(stringsStart);  // Use start of strings
  initialStackFrame.push_back(0);             // null terminator

  size_t stackFrameSize = initialStackFrame.size() * 8;

  // Round the stack offset up to the nearest multiple of 32, as the stack
  // pointer must be aligned to a 32-byte interval on some architectures
  uint64_t stackOffset = alignToBoundary(stackFrameSize, 32);

  stackPointer_ -= stackOffset;

  // Copy initial stack frame to process memory
  char* stackFrameBytes = reinterpret_cast<char*>(initialStackFrame.data());
  std::copy(stackFrameBytes, stackFrameBytes + stackFrameSize,
            processImage_ + stackPointer_);
}

}  // namespace kernel
}  // namespace simeng
