#include "simeng/OS/Process.hh"

#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>

#include "simeng/Elf.hh"
#include "simeng/OS/Constants.hh"
#include "simeng/OS/SimOS.hh"
#include "simeng/memory/Mem.hh"
#include "simeng/util/Math.hh"

namespace simeng {
namespace OS {

uint64_t alignToBoundary(uint64_t value, uint64_t boundary) {
  auto remainder = value % boundary;
  if (remainder == 0) {
    return value;
  }

  return value + (boundary - remainder);
}

Process::Process(
    const std::vector<std::string>& commandLine, SimOS* OS,
    std::vector<RegisterFileStructure> regFileStructure, uint64_t TGID,
    uint64_t TID, sendToMemory sendToMem, size_t simulationMemSize)
    : commandLine_(commandLine),
      TGID_(TGID),
      TID_(TID),
      OS_(OS),
      sendToMem_(sendToMem) {
  // Parse ELF file
  YAML::Node& config = Config::get();
  pageTable_ = std::make_shared<PageTable>();

  // Parse the Elf file.
  assert(commandLine.size() > 0);
  Elf elf(commandLine[0]);
  // if (!elf.isValid()) {
  // return;
  //}

  std::function<uint64_t(uint64_t, size_t)> unmapFn =
      [this](uint64_t vaddr, size_t size) -> uint64_t {
    uint64_t value = pageTable_->deleteMapping(vaddr, size);
    if (value ==
        (masks::faults::pagetable::FAULT | masks::faults::pagetable::UNMAP)) {
      std::cerr << "[SimEng:Process] Mapping doesn't exist for vaddr: " << vaddr
                << " and length: " << size << std::endl;
    }
    return value;
  };

  auto executable = elf.getExecutable();
  auto& elf_ehdr = executable->elf_header;
  auto& elf_phdrs = executable->loadable_phdrs;

  uint64_t min_addr = -1;
  uint64_t max_addr = 0;
  uint64_t phtAddr = 0;

  uint32_t bss = 0;
  uint32_t brk = 0;

  for (auto phdr : elf_phdrs) {
    if ((phdr.p_offset <= elf_ehdr.e_phoff) &&
        (elf_ehdr.e_phoff < phdr.p_offset + phdr.p_filesz)) {
      phtAddr = phdr.p_vaddr + (elf_ehdr.e_phoff - phdr.p_offset);
    }

    min_addr = std::min(min_addr, downAlign(phdr.p_vaddr, 4096));
    max_addr = std::max(max_addr, phdr.p_vaddr + phdr.p_filesz);

    uint32_t temp = phdr.p_vaddr + phdr.p_filesz;
    bss = std::max(bss, temp);

    temp = phdr.p_vaddr + phdr.p_memsz;
    brk = std::max(brk, temp);

    /**
    std::cout << "header" << std::endl;
    std::cout << "start: " << phdr.p_vaddr << std::endl;
    std::cout << "da-start: " << downAlign(phdr.p_vaddr, 4096) << std::endl;
    std::cout << "end: "
              << downAlign(phdr.p_vaddr, 4096) + upAlign(phdr.p_memsz, 4096)
              << std::endl;
    std::cout << "mem-size: " << upAlign(phdr.p_memsz, 4096) << std::endl;
    std::cout << "file-size: " << upAlign(phdr.p_filesz, 4096) << std::endl;
    std::cout << std::endl;
    */
  }
  // std::cout << "End" << std::endl;

  // UpAlign both bss and brk just do we can check if brk > bss
  // if brk > bss then this means some program header in the elf has
  // (p_filesz < p_memsz). This means the remaining portion of (brk - bss) has
  // to be mapped and zeroed out. This behavior is defined in the linux kernel
  // in the load_elf_binary function
  bss = upAlign(bss, 4096);
  brk = upAlign(brk, 4096);

  // Keep stack size to 8MiB
  uint64_t addr_space_end = 1;
  addr_space_end = addr_space_end << 48;

  uint64_t stack_top = addr_space_end;
  uint64_t stack_size = 8 * 1024 * 1024;
  uint64_t stack_end = stack_top - stack_size;

  uint64_t mmap_start = stack_top / 4;

  // We will update stack pointer later.
  memRegion_ = MemRegion(
      stack_top, stack_end, brk, stack_top, mmap_start, stack_top, 0, unmapFn);

  uint64_t paddr = 0;
  uint64_t taddr = 0;

  for (auto phdr : elf_phdrs) {
    uint64_t startAddr = downAlign(phdr.p_vaddr, 4096);
    uint64_t endAddrMemSz = upAlign(phdr.p_vaddr + phdr.p_memsz, 4096);

    uint64_t size = endAddrMemSz - startAddr;

    uint64_t retAddr = memRegion_.mmapRegion(
        startAddr, size, 0, syscalls::mmap::flags::SIMENG_MAP_FIXED,
        HostFileMMap());

    assert(
        retAddr != startAddr &&
        "Address returned from mmapRegion MAP_FIXED is not the same as "
        "supplied arg.");

    // Map each section of the elf and populate the page table.
    paddr = OS_->requestPageFrames(size);
    pageTable_->createMapping(startAddr, paddr, size);

    taddr = pageTable_->translate(phdr.p_vaddr);
    sendToMem_(phdr.data, taddr, phdr.p_filesz);
  }

  // Map the stack and populate the page table.
  memRegion_.mmapRegion(
      stack_top - stack_size, stack_size, 0,
      syscalls::mmap::flags::SIMENG_MAP_FIXED, HostFileMMap());
  paddr = OS_->requestPageFrames(stack_size);
  pageTable_->createMapping(stack_top - stack_size, paddr, stack_size);

  /* Populate the padding between bss and brk;
  if (brk - bss > 0) {
    std::cout << "bss: " << bss << std::endl;
    std::cout << "brk: " << brk << std::endl;
    uint64_t brk_pad_sz = upAlign(brk - bss, 4096);
    uint64_t retAddr = memRegion_.mmapRegion(
        bss, brk_pad_sz, 0, syscalls::mmap::flags::SIMENG_MAP_FIXED,
        HostFileMMap());
    paddr = OS_->requestPageFrames(brk_pad_sz);
    pageTable_->createMapping(retAddr, paddr, brk_pad_sz);
    taddr = pageTable_->translate(bss);
    sendToMem_(std::vector<char>(brk_pad_sz, '\0'), taddr, brk_pad_sz);
  }
  */

  // Populate 1 page for the heap
  uint64_t retAddr = memRegion_.mmapRegion(
      brk, PAGE_SIZE, 0, syscalls::mmap::flags::SIMENG_MAP_FIXED,
      HostFileMMap());
  paddr = OS_->requestPageFrames(PAGE_SIZE);
  pageTable_->createMapping(brk, paddr, PAGE_SIZE);

  uint64_t stackPtr = createStack(stack_top);
  updateStack(stackPtr);

  memRegion_.printVmaList();
  std::cout << "\n StackPtr: " << stackPtr << std::endl;
  /**
  auto interpreter = elf.getInterpreter();
  if (interpreter) {
    for (auto& phdr : interpreter->loadable_phdrs) {
      uint64_t a = phdr.p_vaddr;
      a = -a;
      a += phdr.p_vaddr;
    }
  }
  */
  auto& ehdr = executable->elf_header;
  progHeaderTableAddress_ = phtAddr;
  progHeaderEntSize_ = ehdr.e_phentsize;
  numProgHeaders_ = ehdr.e_phnum;
  entryPoint_ = ehdr.e_entry;

  std::cout << "phdrtable: " << progHeaderTableAddress_ << std::endl;
  std::cout << "phentsz: " << progHeaderEntSize_ << std::endl;
  std::cout << "numhdrs: " << numProgHeaders_ << std::endl;
  std::cout << "entry: " << entryPoint_ << std::endl;

  fdArray_ = std::make_shared<FileDescArray>();
  // Initialise context
  initContext(stackPtr, regFileStructure);
  isValid_ = true;

  // Create `proc/tgid/maps`
  const std::string procTgid_dir =
      specialFilesDir_ + "/proc/" + std::to_string(TGID) + "/";
  mkdir(procTgid_dir.c_str(), 0777);

  std::ofstream tgidMaps_File(procTgid_dir + "maps");
  // Create string for each of the base mappings
  std::stringstream stackStream;
  stackStream << std::setfill('0') << std::hex << std::setw(12) << stack_end
              << "-" << std::setfill('0') << std::hex << std::setw(12)
              << stack_top
              << " rw-p 00000000 00:00 0                          [stack]\n";
  tgidMaps_File << stackStream.str();

  std::stringstream heapStream;
  heapStream << std::setfill('0') << std::hex << std::setw(12) << brk << "-"
             << std::setfill('0') << std::hex << std::setw(12)
             << brk + upAlign(bss - brk, PAGE_SIZE)
             << " rw-p 00000000 00:00 0                          [heap]\n";
  tgidMaps_File << heapStream.str();
  tgidMaps_File.close();

  // std::exit(1);
}

Process::Process(
    span<char> instructions, SimOS* OS,
    std::vector<RegisterFileStructure> regFileStructure, uint64_t TGID,
    uint64_t TID, sendToMemory sendToMem, size_t simulationMemSize)
    : TGID_(TGID), TID_(TID), OS_(OS), sendToMem_(sendToMem) {
  // Leave program command string empty
  commandLine_.push_back("\0");

  pageTable_ = std::make_shared<PageTable>();

  YAML::Node& config = Config::get();
  uint64_t heapSize =
      upAlign(config["Process-Image"]["Heap-Size"].as<uint64_t>(), PAGE_SIZE);
  uint64_t stackSize =
      upAlign(config["Process-Image"]["Stack-Size"].as<uint64_t>(), PAGE_SIZE);
  uint64_t mmapSize =
      upAlign(config["Process-Image"]["Mmap-Size"].as<uint64_t>(), PAGE_SIZE);

  uint64_t instrSize = upAlign(instructions.size(), PAGE_SIZE);
  uint64_t instrEnd = instrSize;

  // Check if the process image can fit inside the simulation memory.
  size_t totalProcLayoutSize = instrSize + heapSize + stackSize + mmapSize;
  if (totalProcLayoutSize > simulationMemSize) {
    std::cerr
        << "[SimEng:Process] Size of the simulation memory is less than the "
           "size of a single process image. Please increase the "
           "{Simulation-Memory: {Size: <size>}} parameter in the YAML model "
           "config file used to run the simulation."
        << std::endl;
    std::exit(1);
  }

  // Heap grows upwards towards higher addresses.
  uint64_t heapStart = instrEnd + PAGE_SIZE;
  uint64_t heapEnd = heapStart + heapSize;

  // Mmap grows upwards towards higher addresses.
  uint64_t mmapStart = heapEnd + PAGE_SIZE;
  uint64_t mmapEnd = mmapStart + mmapSize;

  // Stack grows downwards towards lower addresses.
  uint64_t stackEnd = mmapEnd + PAGE_SIZE;
  uint64_t stackStart = stackEnd + stackSize;
  uint64_t size = stackStart;

  // Request Page frames for heap and stack memory.
  uint64_t instrPhyAddr = OS_->requestPageFrames(instrSize);
  uint64_t heapPhyAddr = OS_->requestPageFrames(heapSize);
  uint64_t stackPhyAddr = OS_->requestPageFrames(stackSize);

  // Create page table mappings for stack and heap virtual address ranges.
  pageTable_->createMapping(0, instrPhyAddr, instrSize);
  pageTable_->createMapping(heapStart, heapPhyAddr, heapSize);
  pageTable_->createMapping(stackEnd, stackPhyAddr, stackSize);

  createStack(stackStart);

  // Create the callback function which will be used by MemRegion to unmap page
  // table mappings upon VMA deletes.
  std::function<uint64_t(uint64_t, size_t)> unmapFn =
      [this](uint64_t vaddr, size_t size) -> uint64_t {
    uint64_t value = pageTable_->deleteMapping(vaddr, size);
    if (value ==
        (masks::faults::pagetable::FAULT | masks::faults::pagetable::UNMAP)) {
      std::cerr << "[SimEng:Process] Mapping doesn't exist for vaddr: " << vaddr
                << " and length: " << size << std::endl;
    }
    return value;
  };

  /**
  memRegion_ = MemRegion(
      stackSize, heapSize, mmapSize, size, stackStart, heapStart, mmapStart,
      stackPtr, unmapFn);

  uint64_t taddr = pageTable_->translate(0);
  sendToMem_(
      std::vector<char>(instructions.begin(), instructions.end()), taddr,
      instructions.size());

  fdArray_ = std::make_shared<FileDescArray>();

  initContext(stackPtr, regFileStructure);
  isValid_ = true;
  */
  std::exit(1);
}

Process::~Process() {}

uint64_t Process::getHeapStart() const { return memRegion_.getHeapStart(); }

uint64_t Process::getStackStart() const { return memRegion_.getProcImgSize(); }

uint64_t Process::getMmapStart() const { return memRegion_.getMmapStart(); }

uint64_t Process::getPageSize() const { return PAGE_SIZE; }

std::string Process::getPath() const { return commandLine_[0]; }

bool Process::isValid() const { return isValid_; }

uint64_t Process::getProcessImageSize() const {
  return memRegion_.getProcImgSize();
}

uint64_t Process::getEntryPoint() const { return entryPoint_; }

uint64_t Process::getStackPointer() const {
  return memRegion_.getInitialStackPtr();
}

uint64_t Process::createStack(uint64_t stackStart) {
  // Decrement the stack pointer and populate with initial stack state
  // (https://www.win.tue.nl/~aeb/linux/hh/stack-layout.html)
  // The argv and env strings are added to the top of the stack first and the
  // lower section of the initial stack is populated from the initialStackFrame
  // vector

  uint64_t stackPointer = stackStart;
  std::vector<uint64_t> initialStackFrame;
  // Stack strings are split into bytes to easily support the injection of null
  // bytes dictating the end of a string
  std::vector<char> stringBytes;

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
  for (size_t i = 0; i < Config::get()["Environment-Variables"].size(); i++) {
    std::string envVar =
        Config::get()["Environment-Variables"][i].as<std::string>();
    for (int i = 0; i < envVar.size(); i++) {
      stringBytes.push_back(envVar.c_str()[i]);
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
  }

  uint64_t paddr = pageTable_->translate(stackPointer);
  sendToMem_(stringBytes, paddr, stringBytes.size());

  initialStackFrame.push_back(0);  // null terminator

  // ELF auxillary vector, keys defined in `uapi/linux/auxvec.h`
  // TODO: populate remaining auxillary vector entries
  initialStackFrame.push_back(auxVec::AT_PHDR);  // AT_PHDR
  initialStackFrame.push_back(progHeaderTableAddress_);

  initialStackFrame.push_back(auxVec::AT_PHENT);  // AT_PHENT
  initialStackFrame.push_back(progHeaderEntSize_);

  initialStackFrame.push_back(auxVec::AT_PHNUM);  // AT_PHNUM
  initialStackFrame.push_back(numProgHeaders_);

  initialStackFrame.push_back(auxVec::AT_PAGESZ);  // AT_PAGESZ
  initialStackFrame.push_back(PAGE_SIZE);

  initialStackFrame.push_back(auxVec::AT_ENTRY);  // AT_ENTRY
  initialStackFrame.push_back(entryPoint_);

  initialStackFrame.push_back(auxVec::AT_NULL);  // null terminator
  initialStackFrame.push_back(0);

  size_t stackFrameSize = initialStackFrame.size() * 8;

  // Round the stack offset up to the nearest multiple of 32, as the stack
  // pointer must be aligned to a 32-byte interval on some architectures
  uint64_t stackOffset = alignToBoundary(stackFrameSize, 32);

  stackPointer -= stackOffset;

  // Copy initial stack frame to process memory
  char* stackFrameBytes = reinterpret_cast<char*>(initialStackFrame.data());
  std::vector<char> data(stackFrameBytes, stackFrameBytes + stackFrameSize);
  paddr = pageTable_->translate(stackPointer);
  sendToMem_(data, paddr, stackFrameSize);
  return stackPointer;
}

uint64_t Process::handlePageFault(uint64_t vaddr) {
  // Retrieve VMA containing the vaddr has raised a page fault.
  VirtualMemoryArea vm = memRegion_.getVMAFromAddr(vaddr);
  // Process VMA doesn't exist. This address is likely due to a speculation.
  if (vm.vmSize_ == 0)
    return masks::faults::pagetable::FAULT |
           masks::faults::pagetable::DATA_ABORT;

  // Round down the memory address to page aligned value to create
  // a page mapping.
  uint64_t alignedVAddr = downAlign(vaddr, PAGE_SIZE);

  uint64_t paddr = OS_->requestPageFrames(PAGE_SIZE);
  uint64_t ret = pageTable_->createMapping(alignedVAddr, paddr, PAGE_SIZE);
  if (ret & masks::faults::pagetable::FAULT)
    return masks::faults::pagetable::FAULT | masks::faults::pagetable::MAP;
  uint64_t taddr = pageTable_->translate(vaddr);

  bool hasFile = vm.hasFile();
  if (!hasFile) return taddr;

  void* filebuf = vm.getFileBuf();

  // Since page fault only allocates a single page it could be possible that a
  // part of the file assosciate with a vma has already been sent to memory. To
  // handle this situation we calculate the offset from VMA start address as
  // this address is also page size aligned.
  uint64_t offset = alignedVAddr - vm.vmStart_;
  size_t writeLen = vm.getFileSize() - (offset);
  writeLen = writeLen > PAGE_SIZE ? PAGE_SIZE : writeLen;

  char* castedFileBuf = static_cast<char*>(filebuf);
  std::vector<char> data(
      castedFileBuf + offset, castedFileBuf + offset + writeLen);
  // send file to memory;
  if (writeLen > 0) {
    sendToMem_(data, paddr, writeLen);
  }
  return taddr;
}

void Process::initContext(
    const uint64_t stackPtr,
    const std::vector<RegisterFileStructure>& regFileStructure) {
  context_.TID = TID_;
  context_.pc = entryPoint_;
  context_.sp = stackPtr;
  context_.progByteLen = getProcessImageSize();
  // Initialise all registers to 0
  size_t numTypes = regFileStructure.size();
  context_.regFile.reserve(numTypes);
  for (size_t type = 0; type < numTypes; type++) {
    uint16_t numTags = regFileStructure[type].quantity;
    uint16_t regBytes = regFileStructure[type].bytes;
    context_.regFile.push_back(
        std::vector<RegisterValue>(numTags, {0, regBytes}));
  }
}

}  // namespace OS
}  // namespace simeng
