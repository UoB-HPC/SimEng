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
                           const std::string coredumpPath,
                           Translator& translator)
    : commandLine_(commandLine), translator_(translator) {
  // Parse ELF file
  assert(commandLine.size() > 0);
  Elf elf(commandLine[0]);
  if (!elf.isValid()) {
    return;
  }
  isValid_ = true;

  // Speculatively parse coredump file
  Elf coredump(coredumpPath);

  entryPoint_ = elf.getEntryPoint();

  // span<char> elfProcessImage = elf.getProcessImage();
  std::vector<ElfHeader> headerContents;
  elf.getContents(headerContents);
  for (const auto& header : headerContents) {
    if (header.type == 1) {
      if (!translator_.add_mapping(
              {header.virtualAddress,
               header.virtualAddress + header.memorySize},
              {simulationHeapStart_,
               simulationHeapStart_ + header.memorySize})) {
        isValid_ = false;
        return;
      }
      simulationHeapStart_ += header.memorySize;
      // #### Won't work for dynamically linked binaries as the stack is a LOAD
      // segment ####
      processHeapStart_ =
          header.virtualAddress + header.memorySize > processHeapStart_
              ? header.virtualAddress + header.memorySize
              : processHeapStart_;
    }
  }

  translator_.setHeapStart(processHeapStart_, simulationHeapStart_);
  // std::cout << "# heapStart_: " << std::hex << simulationHeapStart_ <<
  // std::dec
  //           << " -> " << std::hex << processHeapStart_ << std::dec <<
  //           std::endl;

  translator_.add_mapping({processHeapStart_, processHeapStart_},
                          {simulationHeapStart_, simulationHeapStart_});

  // Align heap start to a 32-byte boundary
  // heapStart_ = alignToBoundary(heapStart_, 32);

  // Set mmap region start to be an equal distance from the stack and heap
  // starts. Additionally, align to the page size (4kb)
  simulationMmapStart_ = alignToBoundary(
      simulationHeapStart_ + (HEAP_SIZE + STACK_SIZE) / 2, pageSize_);
  processMmapStart_ = 0x400000000000;

  // Calculate process image size, including heap + stack
  size_ = simulationHeapStart_ + HEAP_SIZE + STACK_SIZE;

  processImage_ = new char[size_];

  uint64_t lastboundary = 0;

  for (const auto& header : headerContents) {
    if (header.type == 1) {
      std::memcpy(processImage_ + lastboundary, header.content,
                  header.fileSize);
      lastboundary += header.memorySize;
    }
  }

  // for (int i = entryPoint_; i < heapStart_; i++) {
  //   if ((i % 16 == 0)) {
  //     printf("\n%08x  ", i);
  //   }
  //   if ((i != 0) && (i % 16 != 0) && (i % 8 == 0)) {
  //     printf(" ");
  //   }
  //   printf("%02hhx ", processImage_[i]);
  // }

  // Copy ELF process image to process image
  // std::copy(elfProcessImage.begin(), elfProcessImage.end(), processImage_);

  createStack();

  if (!translator_.add_mapping(
          {getStackStart() - STACK_SIZE, getStackStart()},
          {getStackStart() - STACK_SIZE, getStackStart()})) {
    isValid_ = false;
    return;
  }

  // for (int i = 0; i < size_; i++) {
  //   if ((i % 16 == 0)) {
  //     printf("\n%08x  ", i);
  //   }
  //   if ((i != 0) && (i % 16 != 0) && (i % 8 == 0)) {
  //     printf(" ");
  //   }
  //   printf("%02hhx ", processImage_[i]);
  // }
}

LinuxProcess::LinuxProcess(span<char> instructions, Translator& translator)
    : translator_(translator) {
  // Leave program command string empty
  commandLine_.push_back("\0");

  isValid_ = true;

  // Align heap start to a 32-byte boundary
  simulationHeapStart_ = processHeapStart_ =
      alignToBoundary(instructions.size(), 32);

  // Set mmap region start to be an equal distance from the stack and heap
  // starts. Additionally, align to the page size (4kb)
  simulationMmapStart_ = processMmapStart_ = alignToBoundary(
      simulationHeapStart_ + (HEAP_SIZE + STACK_SIZE) / 2, pageSize_);

  translator_.setHeapStart(processMmapStart_, simulationMmapStart_);

  size_ = simulationHeapStart_ + HEAP_SIZE + STACK_SIZE;
  processImage_ = new char[size_];

  std::copy(instructions.begin(), instructions.end(), processImage_);

  if (!translator_.add_mapping({0, processHeapStart_},
                               {0, simulationHeapStart_})) {
    isValid_ = false;
    return;
  }

  translator_.add_mapping({processHeapStart_, processHeapStart_},
                          {simulationHeapStart_, simulationHeapStart_});

  createStack();

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

uint64_t LinuxProcess::getProcessHeapStart() const { return processHeapStart_; }

uint64_t LinuxProcess::getSimulationHeapStart() const {
  return simulationHeapStart_;
}

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
