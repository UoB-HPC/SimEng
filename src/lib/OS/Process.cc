#include "simeng/OS/Process.hh"

#include <unistd.h>

#include <cassert>
#include <cstring>
#include <iostream>

#include "simeng/Elf.hh"
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

  pageTable_ = std::make_shared<PageTable>();

  // Parse the Elf file.
  assert(commandLine.size() > 0);
  Elf elf(commandLine[0]);
  if (!elf.isValid()) {
    return;
  }
  entryPoint_ = elf.getEntryPoint();
  auto headers = elf.getProcessedHeaders();

  std::cout << "Entry Vaddr: " << elf.getEntryPoint() << std::endl;

  // Send all our inital data to memory
  uint64_t maxInitDataAddr = 0;
  int count = 0;

  std::cout << std::endl;
  for (auto header : headers) {
    // Round size to nearest greater pageSize.
    size_t size = roundUpMemAddr(header->memorySize, pageSize_);
    uint64_t vaddr = header->virtualAddress;

    uint64_t avaddr = roundDownMemAddr(vaddr, pageSize_);
    // Request a page frame from the OS.
    uint64_t paddr = os_->requestPageFrames(size);
    // Create a virtual memory mapping.
    pageTable_->createMapping(vaddr, paddr, size);
    // Translate the address of the header virtual address.
    uint64_t translatedAddr = pageTable_->translate(vaddr);

    if (((paddr + size) - translatedAddr) < header->memorySize) {
      paddr = os_->requestPageFrames(pageSize_);
      pageTable_->createMapping(avaddr + size, paddr, pageSize_);
      translatedAddr = pageTable_->translate(vaddr);
    }
    // Send data to memory.
    memory->sendUntimedData(header->headerData, translatedAddr,
                            header->memorySize);

    printf("Header-%d-Min: %llu\n", count, avaddr);
    printf("Header-%d-Max: %llu\n", count, avaddr + size);

    count++;
    // Determine maximum address from headers. Will be used later in determining
    // process layout.
    maxInitDataAddr =
        std::max(maxInitDataAddr, roundUpMemAddr(vaddr + size, pageSize_));
  }

  std::cout << "Entry PAddr: " << pageTable_->translate(elf.getEntryPoint())
            << std::endl;

  // Add Page Size padding
  maxInitDataAddr += pageSize_;
  // Heap grows upwards towards higher addresses.
  heapSize = roundUpMemAddr(heapSize, pageSize_);
  uint64_t heapStart = maxInitDataAddr;
  uint64_t heapEnd = heapStart + heapSize;

  // Mmap grows upwards towards higher addresses.
  uint64_t mmapStart = heapEnd + pageSize_;
  uint64_t mmapSize = pageSize_ * 250 * 1000;
  uint64_t mmapEnd = mmapStart + mmapSize;

  // Stack grows downwards towards lower addresses.
  stackSize = roundUpMemAddr(stackSize, pageSize_);
  uint64_t stackEnd = mmapEnd + pageSize_;
  uint64_t stackStart = stackEnd + stackSize;
  uint64_t size = stackStart;

  // Request Page frames for heap and stack memory.
  uint64_t heapPhyAddr = os_->requestPageFrames(heapEnd - heapStart);
  uint64_t stackPhyAddr = os_->requestPageFrames(stackStart - stackEnd);

  // Create page table mappings for stack and heap virtual address ranges.
  pageTable_->createMapping(stackEnd, stackPhyAddr, stackSize);
  pageTable_->createMapping(heapStart, heapPhyAddr, heapSize);
  uint64_t stackPtr = createStack(stackStart, memory);

  std::cout << "StackStart: " << stackStart << std::endl;
  std::cout << "StackEnd: " << stackEnd << std::endl;
  std::cout << "StackPtr: " << stackPtr << std::endl;
  std::cout << "HeapStart: " << heapStart << std::endl;
  std::cout << "HeapEnd: " << heapEnd << std::endl;
  std::cout << "mmapStart: " << mmapStart << std::endl;
  std::cout << "mmapEnd: " << mmapEnd << std::endl;
  std::cout << std::endl;

  std::function<uint64_t(uint64_t, size_t)> unmapFn =
      [&, this](uint64_t vaddr, size_t size) -> uint64_t {
    uint64_t value = this->pageTable_->deleteMapping(vaddr, size);
    if (value ==
        (masks::faults::pagetable::fault | masks::faults::pagetable::unmap)) {
      std::cerr << "Mapping doesn't exist for vaddr: " << vaddr
                << " and length: " << size << std::endl;
    }
    return value;
  };

  memRegion_ = MemRegion(stackSize, heapSize, mmapSize, size, pageSize_,
                         stackStart, heapStart, mmapStart, stackPtr, unmapFn);

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

  // Set the memory translator.
  memory->setTranslator(getTranslator());
  isValid_ = true;
}

Process::Process(span<char> instructions,
                 std::shared_ptr<simeng::memory::Mem> memory, SimOS* os,
                 std::vector<RegisterFileStructure> regFileStructure,
                 uint64_t TGID, uint64_t TID)
    : os_(os), TGID_(TGID), TID_(TID) {
  // Leave program command string empty
  commandLine_.push_back("\0");

  pageTable_ = std::make_shared<PageTable>();

  YAML::Node& config = Config::get();
  uint64_t heapSize = config["Process-Image"]["Heap-Size"].as<uint64_t>();
  uint64_t stackSize = config["Process-Image"]["Stack-Size"].as<uint64_t>();

  uint64_t instrSize = roundUpMemAddr(instructions.size(), pageSize_);
  uint64_t instrEnd = instrSize;

  // Heap grows upwards towards higher addresses.
  heapSize = roundUpMemAddr(heapSize, pageSize_);
  uint64_t heapStart = instrEnd + 4096;
  uint64_t heapEnd = heapStart + heapSize;

  // Mmap grows upwards towards higher addresses.
  uint64_t mmapStart = heapEnd + pageSize_;
  uint64_t mmapSize = pageSize_ * 250 * 100;
  uint64_t mmapEnd = mmapStart + mmapSize;

  // Stack grows downwards towards lower addresses.
  stackSize = roundUpMemAddr(stackSize, pageSize_);
  uint64_t stackEnd = mmapEnd + pageSize_;
  uint64_t stackStart = stackEnd + stackSize;
  uint64_t size = stackStart;

  // Request Page frames for heap and stack memory.
  uint64_t instrPhyAddr = os_->requestPageFrames(instrSize);
  uint64_t heapPhyAddr = os_->requestPageFrames(heapSize);
  uint64_t stackPhyAddr = os_->requestPageFrames(stackSize);

  // Create page table mappings for stack and heap virtual address ranges.
  pageTable_->createMapping(0, instrPhyAddr, instrSize);
  pageTable_->createMapping(heapStart, heapPhyAddr, heapSize);
  pageTable_->createMapping(stackEnd, stackPhyAddr, stackSize);
  uint64_t stackPtr = createStack(stackStart, memory);

  uint64_t taddr = pageTable_->translate(0);

  std::function<uint64_t(uint64_t, size_t)> unmapFn =
      [&, this](uint64_t vaddr, size_t size) -> uint64_t {
    return this->pageTable_->deleteMapping(vaddr, size);
  };

  memRegion_ = MemRegion(stackSize, heapSize, mmapSize, size, pageSize_,
                         stackStart, heapStart, mmapStart, stackPtr, unmapFn);

  memory->sendUntimedData(instructions.begin(), taddr, instructions.size());

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
  isValid_ = true;
}

Process::~Process() {}

uint64_t Process::getHeapStart() const { return memRegion_.getHeapStart(); }

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
  return memRegion_.getInitialStackPtr();
}

Translator Process::getTranslator() {
  Translator func = [&, this](uint64_t vaddr) -> uint64_t {
    return this->pageTable_->translate(vaddr);
  };
  return func;
}

uint64_t Process::createStack(uint64_t stackStart,
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

uint64_t Process::handlePageFault(uint64_t vaddr, SendToMemory send) {
  VirtualMemoryArea* vm = memRegion_.getVMAFromAddr(vaddr);
  uint64_t alignedVAddr = roundDownMemAddr(vaddr, pageSize_);
  // Process VMA doesn't exist. This address is likely due to a speculation.
  if (vm == NULL)
    return masks::faults::pagetable::fault |
           masks::faults::pagetable::speculation;

  bool hasFile = vm->hasFile();
  uint64_t paddr = os_->requestPageFrames(pageSize_);
  uint64_t ret = pageTable_->createMapping(alignedVAddr, paddr, pageSize_);
  if (ret & masks::faults::pagetable::fault)
    return masks::faults::pagetable::fault | masks::faults::pagetable::map;

  uint64_t taddr = pageTable_->translate(vaddr);
  if (!hasFile) return taddr;

  void* filebuf = vm->getFileBuf();

  uint64_t offset = alignedVAddr - vm->vm_start;
  size_t writeLen = vm->getFileSize() - (offset);
  writeLen = writeLen > pageSize_ ? pageSize_ : writeLen;

  // send file to memory;
  if (writeLen > 0) {
    send((char*)filebuf + offset, paddr, writeLen);
  };
  return taddr;
}

}  // namespace OS
}  // namespace simeng
