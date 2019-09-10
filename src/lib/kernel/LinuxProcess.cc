#include "simeng/kernel/LinuxProcess.hh"

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

LinuxProcess::LinuxProcess(std::string path) : path_(path) {
  // Parse ELF file
  Elf elf(path);
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

std::string LinuxProcess::getPath() const { return path_; }

bool LinuxProcess::isValid() const { return isValid_; }

const span<char> LinuxProcess::getProcessImage() const {
  return {processImage_, size_};
}

uint64_t LinuxProcess::getEntryPoint() const { return entryPoint_; }

uint64_t LinuxProcess::getStackPointer() const { return stackPointer_; }

void LinuxProcess::createStack() {
  // Decrement the stack pointer and populate with initial stack state
  // (https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html)

  uint64_t initialStackFrame[] = {
      // Program arguments
      // TODO: allow defining program arguments
      0,  // argc
      0,  // argv null terminator

      // Environment variable pointers (envp)
      // TODO: pass environment variables to program
      0,  // null terminator

      // ELF auxillary vector, keys defined in `uapi/linux/auxvec.h`
      // TODO: populate remaining auxillary vector entries
      6, 4096,  // AT_PAGESZ -> 4KB
      0         // null terminator
  };

  size_t stackFrameSize = sizeof(initialStackFrame);

  // Round the stack offset up to the nearest multiple of 16, as the stack
  // pointer must be aligned to a 16-byte interval on some architectures
  uint64_t stackOffset = alignToBoundary(stackFrameSize, 16);

  stackPointer_ = getStackStart() - stackOffset;

  char* stackFrameBytes = reinterpret_cast<char*>(initialStackFrame);
  std::copy(stackFrameBytes, stackFrameBytes + stackFrameSize,
            processImage_ + stackPointer_);
}

}  // namespace kernel
}  // namespace simeng
