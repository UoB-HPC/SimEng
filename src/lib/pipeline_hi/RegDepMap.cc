#include "simeng/pipeline_hi/RegDepMap.hh"

#include <iostream>

//#define RDMDEBUG
#ifdef RDMDEBUG
#define DEBUG(x) std::cout << "Core: " << std::hex << x << std::endl;
#else
#define DEBUG(x) do { } while (false);
#endif

namespace simeng {
namespace pipeline_hi {

const Register l_ZERO_REGISTER = {0, 0};

RegDepMap::RegDepMap(const std::vector<RegisterFileStructure> registerFileStructures,
                     const RegisterFileSet& registerFileSet) : 
                registerFileStructures_(registerFileStructures),
                registerFileSet_(registerFileSet) {
  regMap_.resize(registerFileStructures_.size());//Just for Integer Register File for now
  for (size_t type=0; type<registerFileStructures_.size(); type++) {
    regMap_[type].resize(registerFileStructures_.at(type).quantity);
  }
}

RegDepMap::~RegDepMap()
{
  for (unsigned i = 0; i < regMap_.size(); i++) {
    for (unsigned j = 0; j < regMap_[i].size(); j++)
      regMap_[i][j].clear();
    regMap_[i].clear();
  }
  regMap_.clear();
}

void RegDepMap::insert(InstrPtr instr)
{
  //TODO: IRF X0 is not a dependency!
  auto& destinationRegisters = instr->getDestinationRegisters();
  for(const auto& reg: destinationRegisters) {
    if(reg != l_ZERO_REGISTER) { //Not X0
      outstandingDep_++;
      DEBUG("Adding Depencency: addr, 0x" << instr->getInstructionAddress() << std::dec << ", dest: " << reg << ", outstanding: " << outstandingDep_);
      regMap_[reg.type][reg.tag].push_back(instr);
    }
  }
}

void RegDepMap::remove(InstrPtr instr)
{
  auto& destinationRegisters = instr->getDestinationRegisters();
  for(const auto& reg: destinationRegisters) {
    auto it = regMap_[reg.type][reg.tag].begin();
    while (it != regMap_[reg.type][reg.tag].end()) {
      if(*it == instr) {
        outstandingDep_--;
        DEBUG("Removing Depencency: addr, 0x" << instr->getInstructionAddress() << std::dec << ", dest: " << reg << ", outstanding: " << outstandingDep_);
        it = regMap_[reg.type][reg.tag].erase(it);
        break;
      } else {
        it++;
      }
    }
  }
}

bool RegDepMap::canRead(InstrPtr instr)
{
  bool dependency = false;
  auto& sourceRegisters = instr->getOperandRegisters();
  for (uint16_t i = 0; i < sourceRegisters.size(); i++) {
    const auto& srcReg = sourceRegisters[i];

    if (!instr->isOperandReady(i)) {
      // The operand hasn't already been supplied
      if (regMap_[srcReg.type][srcReg.tag].size() == 0) {//pick up value from register file
        instr->supplyOperand(i, registerFileSet_.get(srcReg));         
      } else if (regMap_[srcReg.type][srcReg.tag].back()->hasExecuted() &&
                 !(regMap_[srcReg.type][srcReg.tag].back()->isMul() || regMap_[srcReg.type][srcReg.tag].back()->isDiv() ||
                   (regMap_[srcReg.type][srcReg.tag].back()->isLoad() && !instr->isStoreData()))) {//pick up value from last executed instruction
        const auto& destRegisters = regMap_[srcReg.type][srcReg.tag].back()->getDestinationRegisters();
        const auto& destValues = regMap_[srcReg.type][srcReg.tag].back()->getResults();
        for (size_t j = 0; j < destRegisters.size(); j++) {
          const auto& destReg = destRegisters[j];
          if (destReg == srcReg) {
            instr->supplyOperand(i, destValues[j]);
            break;
          }
        }
      } else {
        dependency = true;
      }
    }
  }

  return !dependency;
}

bool RegDepMap::canWrite(InstrPtr instr)
{
  bool dependency = false;
  auto& destRegisters = instr->getDestinationRegisters();
  for(uint16_t i = 0; i < destRegisters.size(); i++) {
      const auto& destReg = destRegisters[i];
      if (regMap_[destReg.type][destReg.tag].size() > 0 &&
          !regMap_[destReg.type][destReg.tag].back()->hasExecuted()) {
        dependency = true;
        break;
      }
  }
  return !dependency || (instr->isLoad());
}

//Clean up the options logic to ensure all of them work well together
bool RegDepMap::canForward(InstrPtr instr)
{
  return true;
}

void RegDepMap::purgeFlushed() {
  for (auto& registerType : regMap_) {
    for (auto& dependencyList : registerType) {
      auto it = dependencyList.begin();
      while (it != dependencyList.end()) {
        DEBUG("Purge entry present at addr: 0x" << (*it)->getInstructionAddress());
        if ((*it)->isFlushed()) {
          outstandingDep_--;
          it = dependencyList.erase(it);
        } else {
          it++;
        }
      }
    }
  }
}

void RegDepMap::dump()
{
}

}  // namespace pipeline_hi
}  // namespace simeng
