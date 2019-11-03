#include "simeng/kernel/LinuxProcess.hh"

#include <cassert>
#include <cstring>

namespace simeng {
namespace kernel {

/** Align `address` to an `alignTo`-byte boundary by rounding up to the nearest
 * multiple. */
uint64_t alignToBoundary(uint64_t value, uint64_t boundary) {
  auto remainder = value % boundary;
  if (remainder == 0) {
    return value;
  }

  return value + (boundary - remainder);
}

LinuxProcess::LinuxProcess(const std::vector<std::string>& commandLine)
    : commandLine_(commandLine) {
  // Parse ELF file
  assert(commandLine.size() > 0);
  Elf elf(commandLine[0]);
  if (!elf.isValid()) {
    return;
  }
  isValid_ = true;

  entryPoint_ = elf.getEntryPoint();

  span<char> elfProcessImage = elf.getProcessImage();

  // Align heap start to a 16-byte boundary
  heapStart_ = alignToBoundary(elfProcessImage.size(), 16);

  // Calculate process image size, including heap + stack
  size_ = heapStart_ + HEAP_SIZE + STACK_SIZE;
  processImage_ = new char[size_];

  // Copy ELF process image to process image
  std::copy(elfProcessImage.begin(), elfProcessImage.end(), processImage_);

  createStack();
}

LinuxProcess::LinuxProcess(span<char> instructions) {
  // Leave program command string empty
  commandLine_.push_back("\0");

  isValid_ = true;

  // Align heap start to a 16-byte boundary
  heapStart_ = alignToBoundary(instructions.size(), 16);

  size_ = heapStart_ + HEAP_SIZE + STACK_SIZE;
  processImage_ = new char[size_];

  std::copy(instructions.begin(), instructions.end(), processImage_);

  createStack();
}

LinuxProcess::~LinuxProcess() {
  if (isValid_) {
    delete[] processImage_;
  }
}

uint64_t LinuxProcess::getHeapStart() const { return heapStart_; }

uint64_t LinuxProcess::getStackStart() const { return size_; }

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

  stackPointer_ = getStackStart();
  std::vector<uint64_t> initialStackFrame;

  // Program arguments (argc, argv[])
  initialStackFrame.push_back(commandLine_.size());  // argc
  for (size_t i = 0; i < commandLine_.size(); i++) {
    // Push argv[i] to the stack
    size_t argSize = commandLine_[i].size() + 1;
    stackPointer_ -= alignToBoundary(argSize, 16);
    std::memcpy(processImage_ + stackPointer_, commandLine_[i].data(), argSize);

    initialStackFrame.push_back(stackPointer_);  // pointer to argv[i]
  }
  initialStackFrame.push_back(0);  // null terminator

  // Environment variable pointers (envp[])
  // TODO: pass environment variables to program
  initialStackFrame.push_back(0);  // null terminator

  // ELF auxillary vector, keys defined in `uapi/linux/auxvec.h`
  // TODO: populate remaining auxillary vector entries
  initialStackFrame.push_back(6);     // AT_PAGESZ
  initialStackFrame.push_back(4096);  // = 4KB
  initialStackFrame.push_back(0);     // null terminator

  size_t stackFrameSize = initialStackFrame.size() * 8;

  // Round the stack offset up to the nearest multiple of 16, as the stack
  // pointer must be aligned to a 16-byte interval on some architectures
  uint64_t stackOffset = alignToBoundary(stackFrameSize, 16);

  stackPointer_ -= stackOffset;

  // Copy initial stack frame to process memory
  char* stackFrameBytes = reinterpret_cast<char*>(initialStackFrame.data());
  std::copy(stackFrameBytes, stackFrameBytes + stackFrameSize,
            processImage_ + stackPointer_);
}

}  // namespace kernel
}  // namespace simeng
