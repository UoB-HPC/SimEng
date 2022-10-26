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
                           YAML::Node config)
    : STACK_SIZE(config["Process-Image"]["Stack-Size"].as<uint64_t>()),
      HEAP_SIZE(config["Process-Image"]["Heap-Size"].as<uint64_t>()),
      commandLine_(commandLine) {
  // Parse ELF file
  assert(commandLine.size() > 0);
  char* unwrappedProcImgPtr;
  Elf elf(commandLine[0], &unwrappedProcImgPtr);
  if (!elf.isValid()) {
    return;
  }
  isValid_ = true;

  entryPoint_ = elf.getEntryPoint();

  // Align heap start to a 32-byte boundary
  heapStart_ = alignToBoundary(elf.getProcessImageSize(), 32);

  // Set mmap region start to be an equal distance from the stack and heap
  // starts. Additionally, align to the page size (4kb)
  mmapStart_ =
      alignToBoundary(heapStart_ + (HEAP_SIZE + STACK_SIZE) / 2, pageSize_);

  // Calculate process image size, including heap + stack
  size_ = heapStart_ + HEAP_SIZE + STACK_SIZE;

  char* temp = (char*)realloc(unwrappedProcImgPtr, size_ * sizeof(char));
  if (temp == NULL) {
    free(unwrappedProcImgPtr);
    std::cerr << "[SimEng:LinuxProcess] ProcessImage cannot be constructed "
                 "successfully! "
                 "Reallocation failed."
              << std::endl;
    exit(EXIT_FAILURE);
  }
  unwrappedProcImgPtr = temp;

  createStack(&unwrappedProcImgPtr);
  processImage_ = std::shared_ptr<char>(unwrappedProcImgPtr, free);
}

LinuxProcess::LinuxProcess(span<char> instructions, YAML::Node config)
    : STACK_SIZE(config["Process-Image"]["Stack-Size"].as<uint64_t>()),
      HEAP_SIZE(config["Process-Image"]["Heap-Size"].as<uint64_t>()) {
  // Leave program command string empty
  commandLine_.push_back("\0");

  isValid_ = true;

  // Align heap start to a 32-byte boundary
  heapStart_ = alignToBoundary(instructions.size(), 32);

  // Set mmap region start to be an equal distance from the stack and heap
  // starts. Additionally, align to the page size (4kb)
  mmapStart_ =
      alignToBoundary(heapStart_ + (HEAP_SIZE + STACK_SIZE) / 2, pageSize_);

  size_ = heapStart_ + HEAP_SIZE + STACK_SIZE;
  char* unwrappedProcImgPtr = (char*)malloc(size_ * sizeof(char));
  std::copy(instructions.begin(), instructions.end(), unwrappedProcImgPtr);

  createStack(&unwrappedProcImgPtr);
  processImage_ = std::shared_ptr<char>(unwrappedProcImgPtr, free);
}

LinuxProcess::~LinuxProcess() {}

uint64_t LinuxProcess::getHeapStart() const { return heapStart_; }

uint64_t LinuxProcess::getStackStart() const { return size_; }

uint64_t LinuxProcess::getMmapStart() const { return mmapStart_; }

uint64_t LinuxProcess::getPageSize() const { return pageSize_; }

std::string LinuxProcess::getPath() const { return commandLine_[0]; }

bool LinuxProcess::isValid() const { return isValid_; }

std::shared_ptr<char> LinuxProcess::getProcessImage() const {
  return std::shared_ptr<char>(processImage_);
}

uint64_t LinuxProcess::getProcessImageSize() const { return size_; }

uint64_t LinuxProcess::getEntryPoint() const { return entryPoint_; }

uint64_t LinuxProcess::getStackPointer() const { return stackPointer_; }

void LinuxProcess::createStack(char** processImage) {
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
  std::vector<std::string> envStrings = {
      "OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1"};
  for (std::string& env : envStrings) {
    for (int i = 0; i < env.size(); i++) {
      stringBytes.push_back(env.c_str()[i]);
    }
    // Null entry to seperate strings
    stringBytes.push_back(0);
  }

  // Store strings and record both argv and environment pointers
  // Block out stack space for strings to be stored in
  stackPointer_ -= alignToBoundary(stringBytes.size() + 1, 32);
  uint16_t ptrCount = 1;
  initialStackFrame.push_back(stackPointer_);  // argv[0] ptr
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
    (*processImage)[stackPointer_ + i] = stringBytes[i];
  }

  initialStackFrame.push_back(0);  // null terminator

  // ELF auxillary vector, keys defined in `uapi/linux/auxvec.h`
  // TODO: populate remaining auxillary vector entries
  initialStackFrame.push_back(6);  // AT_PAGESZ
  initialStackFrame.push_back(pageSize_);
  initialStackFrame.push_back(0);  // null terminator

  size_t stackFrameSize = initialStackFrame.size() * 8;

  // Round the stack offset up to the nearest multiple of 32, as the stack
  // pointer must be aligned to a 32-byte interval on some architectures
  uint64_t stackOffset = alignToBoundary(stackFrameSize, 32);

  stackPointer_ -= stackOffset;

  // Copy initial stack frame to process memory
  char* stackFrameBytes = reinterpret_cast<char*>(initialStackFrame.data());
  std::copy(stackFrameBytes, stackFrameBytes + stackFrameSize,
            (*processImage) + stackPointer_);
}

}  // namespace kernel
}  // namespace simeng
