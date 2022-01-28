#include "simeng/pipeline/WritebackUnit.hh"

#include <iostream>

namespace simeng {
namespace pipeline {

WritebackUnit::WritebackUnit(
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& completionSlots,
    RegisterFileSet& registerFileSet,
    std::function<void(uint64_t insnId)> flagMicroOpCommits)
    : completionSlots_(completionSlots),
      registerFileSet_(registerFileSet),
      flagMicroOpCommits_(flagMicroOpCommits) {}

void WritebackUnit::tick() {
  for (size_t slot = 0; slot < completionSlots_.size(); slot++) {
    auto& uop = completionSlots_[slot].getHeadSlots()[0];

    if (uop == nullptr) {
      continue;
    }

    auto& results = uop->getResults();
    auto& destinations = uop->getDestinationRegisters();
    // std::cout << "WB: " << uop->getSequenceId() << ":"
    //           << uop->getInstructionId() << ":0x" << std::hex
    //           << uop->getInstructionAddress() << std::dec << ":"
    //           << uop->getMicroOpIndex() << std::endl;
    // std::cout << "WB: 0x" << std::hex << uop->getInstructionAddress()
    //           << std::dec << std::endl;
    for (size_t i = 0; i < results.size(); i++) {
      // Write results to register file
      registerFileSet_.set(destinations[i], results[i]);
      // std::cout << "\t" << unsigned(destinations[i].type) << ":"
      //           << unsigned(destinations[i].tag) << " <- ";
      // if (results[i].size() == 1)
      //   std::cout << unsigned(results[i].get<uint8_t>());
      // else if (results[i].size() == 2)
      //   std::cout << results[i].get<uint16_t>();
      // else if (results[i].size() == 4)
      //   std::cout << results[i].get<uint32_t>();
      // else if (results[i].size() == 8)
      //   std::cout << results[i].get<uint64_t>();
      // else if (results[i].size() == 256)
      //   std::cout << results[i].getAsVector<uint64_t>()[0] << ":"
      //             << results[i].getAsVector<uint64_t>()[1];
      // else
      //   std::cout << "N/A";
      // std::cout << std::endl;
    }
    if (uop->isMicroOp()) {
      uop->setWaitingCommit();
      flagMicroOpCommits_(uop->getInstructionId());
      if (uop->isLastMicroOp()) instructionsWritten_++;
    } else {
      uop->setCommitReady();
      instructionsWritten_++;
    }

    completionSlots_[slot].getHeadSlots()[0] = nullptr;
  }
}

uint64_t WritebackUnit::getInstructionsWrittenCount() const {
  return instructionsWritten_;
}

}  // namespace pipeline
}  // namespace simeng
