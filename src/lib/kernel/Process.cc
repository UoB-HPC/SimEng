#include "simeng/kernel/Process.hh"

#include <unistd.h>

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

Process::Process(const std::vector<std::string>& commandLine, char* memptr,
                 size_t mem_size)
    : commandLine_(commandLine) {
  // Parse ELF file
  assert(commandLine.size() > 0);
  char* unwrappedProcImgPtr;
  Elf elf(commandLine[0], &unwrappedProcImgPtr);
  if (!elf.isValid()) {
    return;
  }
  isValid_ = true;

  entryPoint_ = elf.getEntryPoint();
  YAML::Node& config = Config::get();
  uint64_t heapSize = config["Process-Image"]["Heap-Size"].as<uint64_t>();
  uint64_t stackSize = config["Process-Image"]["Stack-Size"].as<uint64_t>();

  // Align heap start to a 32-byte boundary
  uint64_t heapStart = alignToBoundary(elf.getProcessImageSize(), 32);

  // Set mmap region start to be an equal distance from the stack and heap
  // starts. Additionally, align to the page size (4kb)
  uint64_t mmapStart =
      alignToBoundary(heapStart + (heapSize + stackSize) / 2, pageSize_);

  // Calculate process image size, including heap + stack
  uint64_t size = heapStart + heapSize + stackSize;

  // Check if global memory size is greater than process image size.
  if (mem_size < size) {
    std::cerr << "[SimEng:Process] Memory size is less than size of the "
                 "process image. Please "
                 "increase memory size"
              << std::endl;
    std::exit(1);
  }

  char* temp = (char*)realloc(unwrappedProcImgPtr, size * sizeof(char));
  if (temp == NULL) {
    free(unwrappedProcImgPtr);
    std::cerr << "[SimEng:Process] ProcessImage cannot be constructed "
                 "successfully! "
                 "Reallocation failed."
              << std::endl;
    exit(EXIT_FAILURE);
  }
  unwrappedProcImgPtr = temp;
  memRegion_ =
      MemRegion(stackSize, heapSize, size, 0, heapStart, pageSize_, mmapStart);

  createStack(&unwrappedProcImgPtr);
  // copy process image to global memory.
  memcpy(memptr, unwrappedProcImgPtr, size);
  fileDescriptorTable_.emplace_back(STDIN_FILENO);
  fileDescriptorTable_.emplace_back(STDOUT_FILENO);
  fileDescriptorTable_.emplace_back(STDERR_FILENO);
  // free allocated memory after copy.
  free(unwrappedProcImgPtr);
}

Process::Process(span<char> instructions, char* memptr, size_t mem_size) {
  // Leave program command string empty
  commandLine_.push_back("\0");

  isValid_ = true;
  YAML::Node& config = Config::get();
  uint64_t heapSize = config["Process-Image"]["Heap-Size"].as<uint64_t>();
  uint64_t stackSize = config["Process-Image"]["Stack-Size"].as<uint64_t>();

  // Align heap start to a 32-byte boundary
  uint64_t heapStart = alignToBoundary(instructions.size(), 32);

  // Set mmap region start to be an equal distance from the stack and heap
  // starts. Additionally, align to the page size (4kb)
  uint64_t mmapStart =
      alignToBoundary(heapStart + (heapSize + stackSize) / 2, pageSize_);

  // Calculate process image size, including heap + stack
  uint64_t size = heapStart + heapSize + stackSize;
  // Check if global memory size is greater than process image size.
  if (mem_size < size) {
    std::cerr << "[SimEng:Process] Memory size is less than size of the "
                 "process image. Please "
                 "increase memory size"
              << std::endl;
    std::exit(1);
  }

  char* unwrappedProcImgPtr = (char*)malloc(size * sizeof(char));
  std::copy(instructions.begin(), instructions.end(), unwrappedProcImgPtr);
  memRegion_ =
      MemRegion(stackSize, heapSize, size, 0, heapStart, pageSize_, mmapStart);
  createStack(&unwrappedProcImgPtr);
  // copy process image to global memory.
  memcpy(memptr, unwrappedProcImgPtr, size);
  free(unwrappedProcImgPtr);
}

Process::~Process() {}

uint64_t Process::getHeapStart() const { return memRegion_.getBrkStart(); }

uint64_t Process::getStackStart() const { return memRegion_.getMemSize(); }

uint64_t Process::getMmapStart() const { return memRegion_.getMmapStart(); }

uint64_t Process::getPageSize() const { return pageSize_; }

std::string Process::getPath() const { return commandLine_[0]; }

bool Process::isValid() const { return isValid_; }

uint64_t Process::getProcessImageSize() const {
  return memRegion_.getMemSize();
}

uint64_t Process::getEntryPoint() const { return entryPoint_; }

uint64_t Process::getStackPointer() const {
  return memRegion_.getInitialStackStart();
}

void Process::createStack(char** processImage) {
  // Decrement the stack pointer and populate with initial stack state
  // (https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html)
  // The argv and env strings are added to the top of the stack first and the
  // lower section of the initial stack is populated from the initialStackFrame
  // vector

  uint64_t stackPointer = memRegion_.getMemSize();
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

  // Store strings and record both argv and environment pointers
  // Block out stack space for strings to be stored in
  stackPointer -= alignToBoundary(stringBytes.size() + 1, 32);
  uint16_t ptrCount = 1;
  initialStackFrame.push_back(stackPointer);  // argv[0] ptr
  for (int i = 0; i < stringBytes.size(); i++) {
    if (ptrCount == commandLine_.size()) {
      // null terminator to seperate argv and env strings
      initialStackFrame.push_back(0);
      ptrCount++;
    }
    if (i > 0 && stringBytes[i - 1] == 0x0) {           // i - 1 == null
      initialStackFrame.push_back(stackPointer + (i));  // argv/env ptr
      ptrCount++;
    }
    (*processImage)[stackPointer + i] = stringBytes[i];
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

  stackPointer -= stackOffset;

  // Copy initial stack frame to process memory
  char* stackFrameBytes = reinterpret_cast<char*>(initialStackFrame.data());
  std::copy(stackFrameBytes, stackFrameBytes + stackFrameSize,
            (*processImage) + stackPointer);
  memRegion_.setInitialStackStart(stackPointer);
}

}  // namespace kernel
}  // namespace simeng
