#include "simeng/pipeline/A64FXPortAllocator.hh"

#include <iostream>

namespace simeng {
namespace pipeline {

A64FXPortAllocator::A64FXPortAllocator(
    const std::vector<std::vector<uint16_t>>& portArrangement)
    :  // Initiliase reservation station to port mapping
      rsToPort_({{0, 1, 2}, {3, 4}, {5}, {6}, {7}}) {
  freeEntries_.resize(5);
  dispatchSlots_ = {0, 0, 0, 0, 0, 0, 0, 0, 0};
}

uint16_t A64FXPortAllocator::allocate(const std::vector<uint16_t>& ports,
                                      const uint16_t stallCycles) {
  // if (dispatchSlot_ != 0 && stallCycles == 0)
  //   dispatchSlots_ = {0, 0, 0, 0, 0, 0, 0, 0, 0};
  dispatchSlot_ = stallCycles;
  assert(ports.size() &&
         "No supported ports supplied; cannot allocate from a empty set");
  rsSizes_(freeEntries_);
  defineMF();

  if (print_) {
    std::cerr << "[SimEng] ===[";
    for (const auto& ent : freeEntries_) std::cerr << ent << ",";
    std::cerr << "\b]===[Ports are {";
    for (const auto& pt : ports) std::cerr << pt << ",";
    std::cerr << "\b} and attribute is ";
  }

  if (ports.size() == 1) {
    // dispatchSlot_++;
    if (print_)
      std::cerr << "NA]===[Slot " << dispatchSlot_ << "]\n[SimEng]\tPort is "
                << ports[0] << std::endl;
    return ports[0];
  }
  const uint8_t attribute = attributeMapping(ports);

  if (print_) {
    if (attribute == 0) {
      std::cerr << "RSX";
    } else if (attribute == 1) {
      std::cerr << "RSE";
    } else if (attribute == 2) {
      std::cerr << "RSA";
    } else if (attribute == 3) {
      std::cerr << "RSE0";
    } else if (attribute == 4) {
      std::cerr << "RSE1";
    } else if (attribute == 5) {
      std::cerr << "BR";
    }
    std::cerr << "]===[Slot " << dispatchSlot_ << "]" << std::endl;
  }

  uint16_t rs = 0;
  uint16_t port = 0;
  bool foundRS = false;
  bool foundPort = false;

  if (attribute == InstructionAttribute::RSX) {
    foundRS = true;

    int64_t totRSE = freeEntries_[0] + freeEntries_[1];
    int64_t totRSA = freeEntries_[2] + freeEntries_[3];
    int64_t diffRSE = totRSE - totRSA;
    int64_t diffRSA = totRSA - totRSE;

    bool cond1 =
        (totRSA == 0 && freeEntries_[0] != 0 && freeEntries_[1] != 0) ? 1 : 0;
    bool altCond1 = diffRSE >= cond1Threshold_;
    // cond1 |= altCond1;
    bool cond2 =
        (totRSE == 0 && freeEntries_[2] != 0 && freeEntries_[3] != 0) ? 1 : 0;
    bool altCond2 = diffRSA >= cond2Threshold_;
    // cond2 |= altCond2;
    bool cond3 = std::abs((int64_t)freeEntries_[0] -
                          (int64_t)freeEntries_[1]) >= cond3Threshold_
                     ? 1
                     : 0;
    bool cond4 = true;
    auto entItr = freeEntries_.begin() + 2;
    while (entItr != freeEntries_.end() - 1) {
      if (*entItr >= freeEntries_[RSEm_]) {
        cond4 = false;
        break;
      }
      entItr++;
    }

    uint8_t tableIdx = 0;

    if (cond1 && !cond2) {
      if (cond3)
        tableIdx = 0;
      else
        tableIdx = 1;
    } else if (cond2 && !cond1) {
      tableIdx = 2;
    } else {
      if (cond4)
        tableIdx = 3;
      else
        tableIdx = 4;
    }
    if (print_)
      std::cerr << "[SimEng]\t===[" << cond1 << "|" << cond2 << "|" << cond3
                << "|" << cond4 << " -> " << unsigned(tableIdx) << " with slot "
                << dispatchSlots_[tableIdx] << "]===" << std::endl;

    switch (tableIdx) {
      case 0: {
        rs = RSEm_;
        break;
      }
      case 1: {
        rs = (dispatchSlot_ % 2 == 0) ? RSEm_ : RSEf_;
        break;
      }
      case 2: {
        rs = (dispatchSlot_ % 2 == 0) ? RSAm_ : RSAf_;
        break;
      }
      case 3: {
        if (dispatchSlot_ < 2)
          rs = (dispatchSlot_ == 0) ? RSEm_ : RSEf_;
        else
          rs = (dispatchSlot_ == 2) ? RSAm_ : RSAf_;
        break;
      }
      case 4: {
        if (dispatchSlot_ < 2)
          rs = (dispatchSlot_ == 0) ? RSAm_ : RSAf_;
        else
          rs = (dispatchSlot_ == 2) ? RSEm_ : RSEf_;
        break;
      }
    }

    dispatchSlots_[tableIdx]++;
  } else if (attribute == InstructionAttribute::RSE) {
    foundRS = true;
    if (freeEntries_[RSEm_] != 0 && freeEntries_[RSEf_] == 0) {
      rs = RSEm_;
      dispatchSlots_[5]++;
    } else {
      if (print_)
        std::cerr << "[SimEng] \t===[With slot " << dispatchSlots_[6]
                  << "]===" << std::endl;
      rs = (dispatchSlot_ % 2 == 0) ? 0 : 1;
      dispatchSlots_[6]++;
    }
  } else if (attribute == InstructionAttribute::RSA) {
    foundRS = true;
    if (freeEntries_[RSAm_] != 0 && freeEntries_[RSAf_] == 0) {
      rs = RSAm_;
      dispatchSlots_[7]++;
    } else {
      if (print_)
        std::cerr << "[SimEng] \t===[With slot " << dispatchSlots_[8]
                  << "]===" << std::endl;
      rs = (dispatchSlot_ % 2 == 0) ? 2 : 3;
      dispatchSlots_[8]++;
    }
  } else if (attribute == InstructionAttribute::RSE0) {
    rs = 0;
    foundRS = true;
  } else if (attribute == InstructionAttribute::RSE1) {
    rs = 1;
    foundRS = true;
  } else if (attribute == InstructionAttribute::BR) {
    rs = 4;
    foundRS = true;
  }

  assert(foundRS && "Unsupported group; cannot allocate reservation station");
  // dispatchSlot_++;

  for (auto option : ports) {
    if (std::find(rsToPort_[rs].begin(), rsToPort_[rs].end(), option) !=
        rsToPort_[rs].end()) {
      port = option;
      foundPort = true;
      break;
    }
  }

  assert(foundPort && "Unsupported group; cannot allocate a port");
  if (print_) std::cerr << "[SimEng]\tPort is " << port << std::endl;
  return port;
}

void A64FXPortAllocator::issued(uint16_t port, const uint16_t stallCycles) {}
void A64FXPortAllocator::deallocate(uint16_t port, const uint16_t stallCycles) {
  issued(port);
};

uint8_t A64FXPortAllocator::attributeMapping(
    const std::vector<uint16_t>& ports) {
  uint8_t attribute = 0;
  bool foundAttribute = false;
  if (ports == EXA_EXB_EAGA_EAGB) {  // EXA,EXB,EAGA,EAGB
    attribute = InstructionAttribute::RSX;
    foundAttribute = true;
  } else if (ports == EXA_EXB || ports == FLA_FLB) {  // EXA,EXB|FLA,FLB
    attribute = InstructionAttribute::RSE;
    foundAttribute = true;
  } else if (ports == EAGA_EAGB) {  // EAGA,EAGB
    attribute = InstructionAttribute::RSA;
    foundAttribute = true;
  } else if (ports == EXA || ports == FLA || ports == PR) {  // EXA|FLA|PR
    attribute = InstructionAttribute::RSE0;
    foundAttribute = true;
  } else if (ports == EXB || ports == FLB) {  // EXB|FLB
    attribute = InstructionAttribute::RSE1;
    foundAttribute = true;
  } else if (ports == BR) {  // BR
    attribute = InstructionAttribute::BR;
    foundAttribute = true;
  }

  assert(foundAttribute && "Unsupported group; cannot allocate an attribute");
  return attribute;
}

void A64FXPortAllocator::setRSSizeGetter(
    std::function<void(std::vector<uint64_t>&)> rsSizes) {
  rsSizes_ = rsSizes;
}

void A64FXPortAllocator::tick() {
  // freeEntries_.clear();
  // dispatchSlot_ = 0;
  // dispatchSlots_ = {0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < dispatchSlots_.size(); i++)
    dispatchSlots_[i] = dispatchSlots_[i] % 4;

  if (print_) std::cerr << "[SimEng] ---^---" << std::endl;
}

void A64FXPortAllocator::defineMF() {
  RSEm_ = freeEntries_[0] >= freeEntries_[1] ? 0 : 1;
  RSEf_ = RSEm_ == 0 ? 1 : 0;
  RSAm_ = freeEntries_[2] >= freeEntries_[3] ? 2 : 3;
  RSAf_ = RSAm_ == 2 ? 3 : 2;
}

}  // namespace pipeline
}  // namespace simeng
