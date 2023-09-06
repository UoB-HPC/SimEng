#pragma once

#include <deque>
#include <map>
#include <queue>
#include <unordered_map>

#include "simeng/Instruction.hh"

namespace simeng {
namespace pipeline_hi {

typedef std::shared_ptr<Instruction> InstrPtr;
class RegDepMap
{
  public:
    RegDepMap(const std::vector<RegisterFileStructure> registerFileStructures, 
              const RegisterFileSet& registerFileSet);
    ~RegDepMap();

    /** Clear the Entire Map */
    void clear();

    /** Insert all of a instruction's destination registers into map*/
    void insert(InstrPtr instr);

    /** Remove all of a instruction's destination registers into map*/
    void remove(InstrPtr instr);

    /** Is the current instruction able to read from this
     *  destination register?
     */
    bool canRead(InstrPtr instr);

    /** Is the current instruction able to write to this
     *  destination register?
     */
    bool canWrite(InstrPtr instr);

    /* Is there any instr that can forward the data for this instr. If yes, set
     * the data*/
    bool canForward(InstrPtr instr);

    void purgeFlushed();

    void dump();
    
  private:
    const std::vector<RegisterFileStructure> registerFileStructures_;
    const RegisterFileSet& registerFileSet_;
    typedef std::vector<std::vector<InstrPtr> > DepMap;
    std::vector<DepMap> regMap_;
    uint32_t outstandingDep_ = 0;
};

}  // namespace pipeline_hi
}  // namespace simeng
