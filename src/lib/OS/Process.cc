#include "simeng/OS/Process.hh"

#include <unistd.h>

#include <cassert>
#include <cstring>
#include <iostream>

#include "simeng/OS/SimOS.hh"
#include "simeng/memory/Mem.hh"

namespace simeng {
namespace OS {

uint64_t alignToBoundary(uint64_t value, uint64_t boundary) {
  auto remainder = value % boundary;
  if (remainder == 0) {
    return value;
  }

  return value + (boundary - remainder);
}

Process::Process(const std::vector<std::string>& commandLine,
                 std::shared_ptr<simeng::memory::Mem> memory, SimOS* os,
                 std::vector<RegisterFileStructure> regFileStructure,
                 uint64_t TGID, uint64_t TID)
    : commandLine_(commandLine), os_(os), TGID_(TGID), TID_(TID) {
  // Parse ELF file
  pageTable_ = std ::make_shared<PageTable>();
  assert(commandLine.size() > 0);
  char* unwrappedProcImgPtr;
  Elf elf(commandLine[0], &unwrappedProcImgPtr);
  if (!elf.isValid()) {
    return;
  }
  isValid_ = true;
  std::cout << "Hello" << std::endl;
  entryPoint_ = elf.getEntryPoint();
  YAML::Node& config = Config::get();
  uint64_t heapSize = config["Process-Image"]["Heap-Size"].as<uint64_t>();
  uint64_t stackSize = config["Process-Image"]["Stack-Size"].as<uint64_t>();

  // Align heap start to a 32-byte boundary

  // uint64_t heapStart = alignToBoundary(elf.getProcessImageSize(), 32);

  // Set mmap region start to be an equal distance from the stack and heap
  // starts. Additionally, align to the page size (4kb)

  // uint64_t mmapStart =
  //    alignToBoundary(heapStart + (heapSize + stackSize) / 2, pageSize_);

  // Calculate process image size, including heap + stack

  // uint64_t size = heapStart + heapSize + stackSize;

  // Check if global memory size is greater than process image size.

  /*
  if (memory->getMemorySize() < size) {
    std::cerr << "[SimEng:Process] Memory size is less than size of the "
                 "process image. Please "
                 "increase memory size"
              << std::endl;
    std::exit(1);
  }
  */

  /*
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
  */

  // uint64_t stackPtr = createStack(&unwrappedProcImgPtr, size);
  // memRegion_ = MemRegion(stackSize, heapSize, size, stackPtr, heapStart,
  //                       pageSize_, mmapStart);
  //

  auto headers = elf.getProcessedHeaders();
  // Send all our inital to memory
  uint64_t maxInitDataAddr = 0;
  std::cout << "Hello1" << std::endl;
  for (auto header : headers) {
    size_t size = roundUpMemAddr(header->memorySize, pageSize_);
    uint64_t vaddr = header->virtualAddress;
    uint64_t paddr = os_->requestPageFrames(size);
    pageTable_->createMapping(vaddr, paddr, size);
    uint64_t translatedAddr = pageTable_->translate(vaddr);
    memory->sendUntimedData(header->headerData, translatedAddr,
                            header->memorySize);
    maxInitDataAddr =
        std::max(maxInitDataAddr, roundUpMemAddr(vaddr + size, pageSize_));
  }

  // Add Page Size padding
  maxInitDataAddr += pageSize_;
  // Heap grows upwards towards higher addresses.
  heapSize = roundUpMemAddr(heapSize, pageSize_);
  uint64_t heapStart = maxInitDataAddr;
  uint64_t heapEnd = heapStart + heapSize;
  // Mmap grows upwards towards higher addresses.
  uint64_t mmapStart = heapEnd + pageSize_;
  uint64_t mmapEnd = mmapStart + pageSize_ * 250;
  // Stack grows downwards towards lower addresses.
  stackSize = roundUpMemAddr(stackSize, pageSize_);
  uint64_t stackEnd = mmapEnd + pageSize_;
  uint64_t stackStart = stackEnd + stackSize;
  uint64_t size = stackStart;

  uint64_t heapPhyAddr = os_->requestPageFrames(heapEnd - heapStart);
  uint64_t stackPhyAddr = os_->requestPageFrames(stackStart - stackEnd);

  pageTable_->createMapping(stackEnd, stackPhyAddr, stackSize);
  pageTable_->createMapping(heapStart, heapPhyAddr, heapSize);
  uint64_t stackPtr = createStack(stackStart, memory);

  std::cout << "HeapStart: " << heapStart << std::endl;
  std::cout << "HeapEnd: " << heapEnd << std::endl;
  memRegion_ = MemRegion(stackSize, heapSize, size, stackPtr, heapStart,
                         pageSize_, mmapStart);
  fdArray_ = std::make_shared<FileDescArray>();
  // Initialise context
  context_.TID = TID_;
  context_.pc = entryPoint_;
  context_.sp = stackPtr;
  context_.progByteLen = getProcessImageSize();
  context_.regFile.resize(regFileStructure.size());
  for (size_t i = 0; i < regFileStructure.size(); i++) {
    context_.regFile[i].resize(regFileStructure[i].quantity);
  }
  // Initialise reg values to 0
  for (size_t type = 0; type < context_.regFile.size(); type++) {
    for (size_t tag = 0; tag < context_.regFile[type].size(); tag++) {
      context_.regFile[type][tag] = {0, regFileStructure[type].bytes};
    }
  }
}

Process::Process(span<char> instructions,
                 std::shared_ptr<simeng::memory::Mem> memory, SimOS* os,
                 std::vector<RegisterFileStructure> regFileStructure,
                 uint64_t TGID, uint64_t TID)
    : os_(os), TGID_(TGID), TID_(TID) {
  // Leave program command string empty
  commandLine_.push_back("\0");

  pageTable_ = std::make_shared<PageTable>();

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
  if (memory->getMemorySize() < size) {
    std::cerr << "[SimEng:Process] Memory size is less than size of the "
                 "process image. Please "
                 "increase memory size"
              << std::endl;
    std::exit(1);
  }

  char* unwrappedProcImgPtr = (char*)malloc(size * sizeof(char));
  std::copy(instructions.begin(), instructions.end(), unwrappedProcImgPtr);

  uint64_t stackPtr = createStack(size, memory);
  memRegion_ = MemRegion(stackSize, heapSize, size, stackPtr, heapStart,
                         pageSize_, mmapStart);

  // copy process image to global memory.
  memory->sendUntimedData(unwrappedProcImgPtr, 0, size);
  fdArray_ = std::make_shared<FileDescArray>();
  free(unwrappedProcImgPtr);

  // Initialise context
  context_.TID = TID_;
  context_.pc = entryPoint_;
  context_.sp = stackPtr;
  context_.progByteLen = getProcessImageSize();
  context_.regFile.resize(regFileStructure.size());
  for (size_t i = 0; i < regFileStructure.size(); i++) {
    context_.regFile[i].resize(regFileStructure[i].quantity);
  }
  // Initialise reg values to 0
  for (size_t type = 0; type < context_.regFile.size(); type++) {
    for (size_t tag = 0; tag < context_.regFile[type].size(); tag++) {
      context_.regFile[type][tag] = {0, regFileStructure[type].bytes};
    }
  }
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

Translator Process::getTranslator() {
  Translator func = [&, this](uint64_t vaddr) -> uint64_t {
    return this->pageTable_->translate(vaddr);
  };
  return func;
}

uint64_t Process::createStack(uint64_t& stackStart,
                              std::shared_ptr<simeng::memory::Mem>& memory) {
  // Decrement the stack pointer and populate with initial stack state
  // (https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html)
  // The argv and env strings are added to the top of the stack first and the
  // lower section of the initial stack is populated from the initialStackFrame
  // vector

  uint64_t stackPointer = stackStart;
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
    uint64_t paddr = pageTable_->translate(stackPointer + i);
    memory->sendUntimedData(reinterpret_cast<char*>(&stringBytes[i]), paddr,
                            sizeof(uint8_t));
    // (*processImage)[stackPointer + i] = stringBytes[i];
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
  uint64_t paddr = pageTable_->translate(stackPointer);
  memory->sendUntimedData(stackFrameBytes, paddr, stackFrameSize);

  // std::copy(stackFrameBytes, stackFrameBytes + stackFrameSize,
  //          (*processImage) + stackPointer);

  return stackPointer;
}

}  // namespace OS
}  // namespace simeng
