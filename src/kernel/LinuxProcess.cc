#include "LinuxProcess.hh"

namespace simeng {
namespace kernel {

LinuxProcess::LinuxProcess(std::string path) {
  // Parse ELF file
  Elf elf(path);
  if (!elf.isValid()) {
    return;
  }
  isValid_ = true;

  entryPoint_ = elf.getEntryPoint();

  span<char> elfProcessImage = elf.getProcessImage();

  heapStart_ = elfProcessImage.size();

  // Calculate process image size, including heap + stack
  size_ = heapStart_ + HEAP_SIZE + STACK_SIZE;
  processImage_ = new char[size_];

  // Copy ELF process image to process image
  std::copy(elfProcessImage.begin(), elfProcessImage.end(), processImage_);

  createStack();
}

LinuxProcess::LinuxProcess(span<char> instructions) {
  isValid_ = true;
  heapStart_ = instructions.size();
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

bool LinuxProcess::isValid() const { return isValid_; }

const span<char> LinuxProcess::getProcessImage() const {
  return {processImage_, size_};
}

uint64_t LinuxProcess::getEntryPoint() const { return entryPoint_; }

uint64_t LinuxProcess::getStackPointer() const { return stackPointer_; }

void LinuxProcess::createStack() {
  // Decrement the stack pointer and populate with initial stack state
  // (https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html)

  // TODO: allow defining process arguments

  uint64_t initialStackFrame[] = {// argc, 0
                                  0,
                                  // argv null terminator
                                  0,
                                  // no environment pointers (envp)
                                  // environment pointers null terminator
                                  0,
                                  // ELF auxillary data end-of-table
                                  0};

  size_t stackFrameSize = sizeof(initialStackFrame);
  uint64_t stackOffset = stackFrameSize;

  // Round the stack offset up to the nearest multiple of 16, as the stack
  // pointer must be aligned to a 16-byte interval on some architectures
  uint64_t remainder = stackFrameSize % 16;
  if (remainder != 0) {
    stackOffset += remainder;
  }

  stackPointer_ = getStackStart() - stackOffset;

  char* stackFrameBytes = reinterpret_cast<char*>(initialStackFrame);
  std::copy(stackFrameBytes, stackFrameBytes + sizeof(stackFrameBytes),
            processImage_ + stackPointer_);
}

}  // namespace kernel
}  // namespace simeng
