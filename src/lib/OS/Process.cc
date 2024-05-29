#include "simeng/OS/Process.hh"

#include <unistd.h>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "simeng/Elf.hh"
#include "simeng/OS/Constants.hh"
#include "simeng/OS/SimOS.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/config/SimInfo.hh"
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

Process::Process(SimOS* OS, uint64_t TGID, uint64_t TID, sendToMemory sendToMem)
    : fdArray_(std::make_shared<FileDescArray>()),
      TGID_(TGID),
      TID_(TID),
      pageTable_(std::make_shared<PageTable>()),
      OS_(OS),
      sendToMem_(sendToMem) {}

Process::~Process() {}

uint64_t Process::getHeapStart() const { return memRegion_->getHeapStart(); }

uint64_t Process::getMmapStart() const { return memRegion_->getMmapBase(); }

uint64_t Process::getPageSize() const { return PAGE_SIZE; }

std::string Process::getPath() const { return commandLine_[0]; }

bool Process::isValid() const { return isValid_; }

uint64_t Process::getProcessImageSize() const {
  return memRegion_->getProcessImgSize();
}

uint64_t Process::getEntryPoint() const {
  return isDynamic_ ? interpEntryPoint_ : elfEntryPoint_;
}

uint64_t Process::getStackPointer() const { return initStackPtr_; }

void Process::loadInstructions(span<char>& instructions, size_t simMemSize) {
  ryml::ConstNodeRef config = config::SimInfo::getConfig();
  uint64_t heapSize;
  config["Process-Image"]["Heap-Size"] >> heapSize;
  heapSize = upAlign(heapSize, PAGE_SIZE);
  uint64_t stackSize;
  config["Process-Image"]["Stack-Size"] >> stackSize;
  stackSize = upAlign(stackSize, PAGE_SIZE);
  uint64_t mmapSize;
  config["Process-Image"]["Mmap-Size"] >> mmapSize;
  mmapSize = upAlign(mmapSize, PAGE_SIZE);

  uint64_t instrStart = PAGE_SIZE;
  uint64_t instrSize = upAlign(instructions.size(), PAGE_SIZE);
  uint64_t brk = instrSize;

  // Check if the process image can fit inside the simulation memory.
  size_t totalProcLayoutSize = instrSize + heapSize + stackSize + mmapSize;
  if (totalProcLayoutSize > simMemSize) {
    std::cerr
        << "[SimEng:Process] Size of the simulation memory is less than the "
           "size of a single process image. Please increase the "
           "{Memory-Hierarchy:{DRAM:{Size}}} parameter in the YAML model "
           "config file used to run the simulation."
        << std::endl;
    std::exit(1);
  }

  // Mmap grows upwards towards higher addresses.
  uint64_t mmapBase = brk + heapSize + mmapSize;
  uint64_t stackGuardAddr = mmapBase;

  // Stack grows downwards towards lower addresses.
  uint64_t stackEnd = stackGuardAddr + (10 * PAGE_SIZE);
  uint64_t stackTop = stackEnd + stackSize;

  // Create the callback function which will be used by MemRegion to unmap
  // page table mappings upon VMA deletes.
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
  memRegion_ = std::make_shared<MemRegion>(brk, mmapBase, PAGE_SIZE,
                                           stackGuardAddr, stackTop, unmapFn);
  // Map instructions
  uint64_t retAddr = memRegion_->mmapRegion(
      instrStart, instrSize, 0, syscalls::mmap::flags::SIMENG_MAP_FIXED,
      HostFileMMap());
  uint64_t instrPhyAddr = OS_->requestPageFrames(instrSize);
  pageTable_->createMapping(retAddr, instrPhyAddr, instrSize);

  // Map the stack
  retAddr = memRegion_->mmapRegion(stackEnd, stackSize, 0,
                                   syscalls::mmap::flags::SIMENG_MAP_FIXED,
                                   HostFileMMap());
  uint64_t stackPhyAddr = OS_->requestPageFrames(stackSize);
  pageTable_->createMapping(retAddr, stackPhyAddr, stackSize);
  uint64_t taddr = pageTable_->translate(instrStart);
  sendToMem_(std::vector<char>(instructions.begin(), instructions.end()), taddr,
             instrStart, instructions.size());

  initStackPtr_ = createStack(stackTop);
}

void Process::loadElf(Elf& elf) {
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
  }
  pageTable_->ignoreAddrRange(0, min_addr);

  // UpAlign both bss and brk just do we can check if brk > bss
  // if brk > bss then this means some program header in the elf has
  // (p_filesz < p_memsz). This means the remaining portion of (brk - bss) has
  // to be mapped and zeroed out. This behavior is defined in the linux kernel
  // in the load_elf_binary function
  bss = upAlign(bss, 4096);
  brk = upAlign(brk, 4096);

  uint64_t paddr = 0;
  uint64_t taddr = 0;

  for (auto phdr : elf_phdrs) {
    uint64_t startAddr = downAlign(phdr.p_vaddr, 4096);
    uint64_t endAddrMemSz = upAlign(phdr.p_vaddr + phdr.p_memsz, 4096);

    uint64_t size = endAddrMemSz - startAddr;

    uint64_t retAddr = memRegion_->mmapRegion(
        startAddr, size, 0, syscalls::mmap::flags::SIMENG_MAP_FIXED,
        HostFileMMap());

    assert(retAddr == startAddr &&
           "Address returned from mmapRegion MAP_FIXED is not the same as "
           "supplied arg.");

    // Map each section of the elf and populate the page table.
    paddr = OS_->requestPageFrames(size);
    pageTable_->createMapping(startAddr, paddr, size);

    taddr = pageTable_->translate(phdr.p_vaddr);
    sendToMem_(phdr.data, taddr, phdr.p_vaddr, phdr.p_filesz);
  }

  if (brk > bss) {
    memRegion_->mmapRegion(bss, brk - bss, 0,
                           syscalls::mmap::flags::SIMENG_MAP_FIXED,
                           HostFileMMap());
    uint64_t phyaddr = OS_->requestPageFrames(brk - bss);
    pageTable_->createMapping(bss, phyaddr, brk - bss);
  }

  auto& ehdr = executable->elf_header;
  progHeaderTableAddress_ = phtAddr;
  progHeaderEntSize_ = ehdr.e_phentsize;
  numProgHeaders_ = ehdr.e_phnum;
  elfEntryPoint_ = ehdr.e_entry;
  if (elf.getInterpreter()) {
    loadInterpreter(elf);
  }
}

void Process::loadInterpreter(Elf& elf) {
  auto interpreter = elf.getInterpreter();
  auto& interp_ehdr = interpreter->elf_header;
  bool addr_not_set = true;

  uint64_t bss = 0;
  uint64_t brk = 0;

  isDynamic_ = true;
  interpEntryPoint_ = 0;

  uint64_t min_addr = -1;
  uint64_t max_addr = 0;
  for (auto phdr : interpreter->loadable_phdrs) {
    min_addr = std::min(min_addr, downAlign(phdr.p_vaddr, 4096));
    max_addr = std::max(max_addr, upAlign(phdr.p_vaddr + phdr.p_memsz, 4096));
  }

  uint64_t total_map_size = max_addr - min_addr;

  uint64_t map_addr =
      memRegion_->mmapRegion(min_addr, total_map_size, 0, 0, HostFileMMap());

  for (auto& phdr : interpreter->loadable_phdrs) {
    uint64_t startAddr = map_addr + downAlign(phdr.p_vaddr, 4096);
    uint64_t endAddrMemSz =
        map_addr + upAlign(phdr.p_vaddr + phdr.p_memsz, 4096);

    uint64_t size = endAddrMemSz - startAddr;

    bss = std::max(bss, startAddr + phdr.p_filesz);
    brk = std::max(brk, startAddr + phdr.p_memsz);

    // We need to add an offset to the address returned by mmap
    // call to find the virtual address corresponding the entry
    // point of the interpreter.
    uint64_t paddr = OS_->requestPageFrames(size);
    pageTable_->createMapping(startAddr, paddr, size);

    uint64_t taddr = pageTable_->translate(phdr.p_vaddr + map_addr);
    sendToMem_(phdr.data, taddr, phdr.p_vaddr + map_addr, phdr.p_filesz);
  }
  interpEntryPoint_ = map_addr + interp_ehdr.e_entry;

  if (upAlign(brk, PAGE_SIZE) > upAlign(bss, PAGE_SIZE)) {
    bss = downAlign(bss, PAGE_SIZE);
    memRegion_->mmapRegion(bss, brk - bss, 0,
                           syscalls::mmap::flags::SIMENG_MAP_FIXED,
                           HostFileMMap());
  }
}

uint64_t Process::getBrkFromElf(Elf& elf) {
  auto loadable_headers = elf.getExecutable()->loadable_phdrs;
  uint64_t brk = 0;
  for (auto& phdr : loadable_headers) {
    brk = std::max(brk, phdr.p_vaddr + phdr.p_memsz);
  }
  return upAlign(brk, PAGE_SIZE);
}

void Process::mapStack(uint64_t stack_top, uint64_t stack_size) {
  memRegion_->mmapRegion(stack_top - stack_size, stack_size, 0,
                         syscalls::mmap::flags::SIMENG_MAP_FIXED,
                         HostFileMMap());

  uint64_t paddr = OS_->requestPageFrames(stack_size);
  pageTable_->createMapping(stack_top - stack_size, paddr, stack_size);
}

template <>
uint64_t Process::setupMemRegion<arch::aarch64::Architecture>(uint64_t brk) {
  uint64_t stack_top = 1;
  stack_top = stack_top << 48;
  uint64_t stack_size = 8 * 1024 * 1024;
  uint64_t stack_end = stack_top - stack_size;
  uint64_t stack_guard_gap = (256 << 12);

  uint64_t mmap_base = stack_end - stack_guard_gap;
  uint64_t mmap_end = PAGE_SIZE;

  // Create the callback function which will be used by MemRegion to unmap
  // page table mappings upon VMA deletes.
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

  memRegion_ = std::make_shared<MemRegion>(brk, mmap_base, mmap_end, mmap_base,
                                           stack_top, unmapFn);
  mapStack(stack_top, stack_size);
  return stack_top;
}

template <>
uint64_t Process::setupMemRegion<arch::riscv::Architecture>(uint64_t brk) {
  // The comment below has been referenced from:
  // https://elixir.bootlin.com/linux/v6.3.9/source/arch/riscv/include/asm/pgtable.h#L793

  /*
   * Task size is 0x4000000000 for RV64 or 0x9fc00000 for RV32.
   * Note that PGDIR_SIZE must evenly divide TASK_SIZE.
   * Task size is:
   * -     0x9fc00000 (~2.5GB) for RV32.
   * -   0x4000000000 ( 256GB) for RV64 using SV39 mmu
   * - 0x800000000000 ( 128TB) for RV64 using SV48 mmu
   *
   * Note that PGDIR_SIZE must evenly divide TASK_SIZE since "RISC-V
   * Instruction Set Manual Volume II: Privileged Architecture" states that
   * "load and store effective addresses, which are 64bits, must have bits
   * 63–48 all equal to bit 47, or else a page-fault exception will occur."
   */

  uint64_t stack_top = 0x00007fffffffffff;
  uint64_t stack_size = 8 * 1024 * 1024;
  uint64_t stack_end = stack_top - stack_size;
  uint64_t stack_guard_gap = (256 << 12);

  uint64_t mmap_base = stack_end - stack_guard_gap;
  uint64_t mmap_end = PAGE_SIZE;

  // Create the callback function which will be used by MemRegion to unmap
  // page table mappings upon VMA deletes.
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

  memRegion_ = std::make_shared<MemRegion>(brk, mmap_base, mmap_end, mmap_base,
                                           stack_top, unmapFn);
  mapStack(stack_top, stack_size);
  return stack_top;
}

void Process::initContext(const uint64_t stackPtr) {
  auto regFileStructure = config::SimInfo::getArchRegStruct();

  context_.TID = TID_;
  context_.pc = getEntryPoint();
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

template <>
void Process::archSetup<arch::aarch64::Architecture>() {
  // Set the stack pointer register
  context_.regFile[arch::aarch64::RegisterType::GENERAL][31] = {context_.sp, 8};
  // Set the system registers
  // Temporary: state that DCZ can support clearing 64 bytes at a time,
  // but is disabled due to bit 4 being set
  context_.regFile[arch::aarch64::RegisterType::SYSTEM]
                  [config::SimInfo::getSysRegVecIndex(
                      arm64_sysreg::ARM64_SYSREG_DCZID_EL0)] = {
      static_cast<uint64_t>(0b10100), 8};
}

template <>
void Process::archSetup<arch::riscv::Architecture>() {
  // Set the stack pointer register
  context_.regFile[arch::riscv::RegisterType::GENERAL][2] = {context_.sp, 8};
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
  ryml::ConstNodeRef config = config::SimInfo::getConfig();
  for (size_t i = 0; i < config["Environment-Variables"].num_children(); i++) {
    std::string envVar;
    config["Environment-Variables"][i] >> envVar;
    for (int i = 0; i < envVar.size(); i++) {
      stringBytes.push_back(envVar.c_str()[i]);
    }
    // Null entry to seperate strings
    stringBytes.push_back(0);
  }

  // Add loader specific environemnt variables.
  if (isDynamic_) {
    std::vector<std::string> ld_env_vars;
    const auto& ld_lib_path_node = config["Interpreter"]["LD_LIBRARY_PATH"];
    const auto& ld_extra_env_vars_node =
        config["Interpreter"]["Extra-Env-Vars"];

    // Build LD_LIBRARY_PATH
    std::string ld_lib_path = "LD_LIBRARY_PATH=";
    for (size_t x = 0; x < ld_lib_path_node.num_children(); x++) {
      std::string ld_lib_path_node_str;
      ld_lib_path_node[x] >> ld_lib_path_node_str;
      ld_lib_path += ld_lib_path_node_str;
      ld_lib_path += ":";
    }
    // Remove semicolon at the end of the string
    ld_lib_path.pop_back();
    std::cerr << ld_lib_path << std::endl;
    ld_env_vars.push_back(ld_lib_path);

    // Add any extra specified environment variables
    for (size_t x = 0; x < ld_extra_env_vars_node.num_children(); x++) {
      std::string ld_extra_env_vars_node_str;
      ld_extra_env_vars_node[x] >> ld_extra_env_vars_node_str;
      ld_env_vars.push_back(ld_extra_env_vars_node_str);
    }

    // Add debug environment variables for the interpreter, if specified.
    bool interp_debug_mode;
    config["Interpreter"]["Debug"] >> interp_debug_mode;
    if (interp_debug_mode) {
      ld_env_vars.push_back("LD_DEBUG=all");
      ld_env_vars.push_back("LD_VERBOSE=1");
      ld_env_vars.push_back("LD_SHOW_AUXV=1");
    }

    // Add interpreter environment variables to the environment variables list.
    for (auto& ld_env_var : ld_env_vars) {
      for (auto& ch : ld_env_var) {
        stringBytes.push_back(ch);
      }
      // Null entry to seperate strings
      stringBytes.push_back(0);
    }
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
  sendToMem_(stringBytes, paddr, stackPointer, stringBytes.size());

  initialStackFrame.push_back(0);  // null terminator

  // ELF auxillary vector, keys defined in `uapi/linux/auxvec.h`
  // TODO: populate remaining auxillary vector entries
  initialStackFrame.push_back(auxVec::AT_PAGESZ);  // AT_PAGESZ
  initialStackFrame.push_back(PAGE_SIZE);

  initialStackFrame.push_back(auxVec::AT_PHDR);  // AT_PHDR
  initialStackFrame.push_back(progHeaderTableAddress_);

  initialStackFrame.push_back(auxVec::AT_PHENT);  // AT_PHENT
  initialStackFrame.push_back(progHeaderEntSize_);

  initialStackFrame.push_back(auxVec::AT_PHNUM);  // AT_PHNUM
  initialStackFrame.push_back(numProgHeaders_);

  initialStackFrame.push_back(auxVec::AT_BASE);  // AT_BASE
  initialStackFrame.push_back(interpEntryPoint_);

  initialStackFrame.push_back(auxVec::AT_ENTRY);  // AT_ENTRY
  initialStackFrame.push_back(elfEntryPoint_);

  initialStackFrame.push_back(auxVec::AT_NULL);  // null terminator
  initialStackFrame.push_back(0);

  size_t stackFrameSize = initialStackFrame.size() * 8;

  // Round the stack offset up to the nearest multiple of 16, as the stack
  // pointer must be aligned to a 16-byte interval on some architectures
  uint64_t stackOffset = alignToBoundary(stackFrameSize, 32);

  stackPointer -= stackOffset;

  // Copy initial stack frame to process memory
  char* stackFrameBytes = reinterpret_cast<char*>(initialStackFrame.data());
  std::vector<char> data(stackFrameBytes, stackFrameBytes + stackFrameSize);
  paddr = pageTable_->translate(stackPointer);
  sendToMem_(data, paddr, stackPointer, stackFrameSize);
  return stackPointer;
}

uint64_t Process::handlePageFault(uint64_t vaddr) {
  // Retrieve VMA containing the vaddr has raised a page fault.
  VirtualMemoryArea vm = memRegion_->getVMAFromAddr(vaddr);
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
  uint64_t fileBufSize = vm.getFileSize();
  if (offset > fileBufSize) {
    sendToMem_(std::vector<char>(PAGE_SIZE, '\0'), paddr, vaddr, PAGE_SIZE);
    return taddr;
  }

  uint64_t writeLen =
      (fileBufSize - offset) > PAGE_SIZE ? PAGE_SIZE : (fileBufSize - offset);

  char* castedFileBuf = static_cast<char*>(filebuf);
  std::vector<char> data(castedFileBuf + offset,
                         castedFileBuf + offset + writeLen);
  // send file to memory;
  if (writeLen > 0) {
    sendToMem_(data, paddr, vaddr, writeLen);
  }
  if (writeLen < PAGE_SIZE) {
    sendToMem_(std::vector<char>(PAGE_SIZE - writeLen, '\0'), paddr + writeLen,
               vaddr + writeLen, PAGE_SIZE - writeLen);
  }
  return taddr;
}
}  // namespace OS
}  // namespace simeng
