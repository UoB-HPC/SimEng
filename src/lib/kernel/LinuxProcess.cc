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
                           ryml::ConstNodeRef config)
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

  progHeaderTableAddress_ = elf.getPhdrTableAddress();
  progHeaderEntSize_ = elf.getPhdrEntrySize();
  numProgHeaders_ = elf.getNumPhdr();

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

// TODO can this be marked as only usable by test? or is it used by SST??
LinuxProcess::LinuxProcess(span<const uint8_t> instructions,
                           ryml::ConstNodeRef config)
    : STACK_SIZE(config["Process-Image"]["Stack-Size"].as<uint64_t>()),
      HEAP_SIZE(config["Process-Image"]["Heap-Size"].as<uint64_t>()) {
  // Set program command string to a relative path of "Default"
  // TODO need to determine consequences of setting this as absolute and
  // relative to simeng source directory. Should the default prog be in the
  // source or copied to the build dir?
  commandLine_.push_back(SIMENG_SOURCE_DIR "/SimEngDefaultProgram\0");
  //  std::cerr << "command line = " << commandLine_.back().c_str() <<
  //  std::endl;

  isValid_ = true;

  // Align heap start to a 32-byte boundary
  heapStart_ = alignToBoundary(instructions.size(), 32);

  // Set mmap region start to be an equal distance from the stack and heap
  // starts. Additionally, align to the page size (4kb)
  mmapStart_ =
      alignToBoundary(heapStart_ + (HEAP_SIZE + STACK_SIZE) / 2, pageSize_);

  size_ = heapStart_ + HEAP_SIZE + STACK_SIZE;
  char* unwrappedProcImgPtr = (char*)calloc(size_, sizeof(char));
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

uint64_t LinuxProcess::getInitialStackPointer() const { return stackPointer_; }

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
    for (size_t j = 0; j < commandLine_[i].size(); j++) {
      stringBytes.push_back(argvi[j]);
    }
    stringBytes.push_back(0);
  }
  // Environment strings
  std::vector<std::string> envStrings = {"OMP_NUM_THREADS=1"};
  for (std::string& env : envStrings) {
    for (size_t i = 0; i < env.size(); i++) {
      stringBytes.push_back(env.c_str()[i]);
    }
    // Null entry to separate strings
    stringBytes.push_back(0);
  }

  // Store strings and record both argv and environment pointers
  // Block out stack space for strings to be stored in
  stackPointer_ -= alignToBoundary(stringBytes.size() + 1, 32);
  uint16_t ptrCount = 1;
  initialStackFrame.push_back(stackPointer_);  // argv[0] ptr
  for (size_t i = 0; i < stringBytes.size(); i++) {
    if (ptrCount == commandLine_.size()) {
      // null terminator to separate argv and env strings
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

  // ELF auxiliary vector, keys defined in `uapi/linux/auxvec.h`
  // TODO: populate remaining auxiliary vector entries
  initialStackFrame.push_back(auxVec::AT_PHDR);  // AT_PHDR
  initialStackFrame.push_back(progHeaderTableAddress_);

  initialStackFrame.push_back(auxVec::AT_PHENT);  // AT_PHENT
  initialStackFrame.push_back(progHeaderEntSize_);

  initialStackFrame.push_back(auxVec::AT_PHNUM);  // AT_PHNUM
  initialStackFrame.push_back(numProgHeaders_);

  initialStackFrame.push_back(auxVec::AT_PAGESZ);  // AT_PAGESZ
  initialStackFrame.push_back(pageSize_);

  initialStackFrame.push_back(auxVec::AT_ENTRY);  // AT_ENTRY
  initialStackFrame.push_back(entryPoint_);

  initialStackFrame.push_back(auxVec::AT_NULL);  // null terminator
  initialStackFrame.push_back(0);

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
