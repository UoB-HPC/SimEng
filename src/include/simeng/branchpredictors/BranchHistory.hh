#pragma once

#include <iostream>

namespace simeng {
/** A class for storing a branch history.  Needed for cases where a branch
 * history of more than 64 bits is required.  This class makes it easier to
 * access and manipulate large branch histories, as are needed in
 * sophisticated branch predictors.
 *
 * The bits of the branch history are stored in a vector of uint64_t values,
 * and their access/manipulation is facilitated by the public functions.*/

class BranchHistory {
 public:
  BranchHistory(uint64_t size) : size_(size) {
    history_ = {0};
    for (uint8_t i = 0; i < (size_ / 64); i++) {
      history_.push_back(0);
    }
  }
  ~BranchHistory() {};

  /** Returns the numBits most recent bits of the branch history.  Maximum
   * number of bits returnable is 64 to allow it to be provided in a 64-bit
   * integer. */
  uint64_t getHistory(uint8_t numBits) {
//    std::cout << "getHistory" << std::endl;
    assert(numBits <= 64 && "Cannot get more than 64 bits without rolling");
    assert(numBits <= size_ && "Cannot get more bits of branch history than "
           "the size of the history");
    return (history_[0] & ((1 << numBits) - 1));
  }

  /** returns the global history folded over on itself to get a bitmap of the
   * size specified by numBits.  The global history is folded by taking an
   * XOR hash with the overflowing bits.
   * */
  uint64_t getFolded(uint8_t numBits) {
//    std::cout << "getFolded" << std::endl;
    assert(numBits <= size_ && "Cannot get more bits of branch history than "
           "the size of the history");
    uint64_t output = 0;

    uint64_t startIndex = 0;
    uint64_t endIndex = numBits - 1;

    while (startIndex <= size_) {
      output ^= (history_[startIndex / 64] >> startIndex);

      // Check to see if a second uint64_t value will need to be accessed
      if ((startIndex / 64) == (endIndex / 64)) {
        uint8_t leftOverBits = endIndex % 64;
        output ^= (history_[endIndex / 64] << (numBits - leftOverBits));
      }
      startIndex += numBits;
      endIndex += numBits;
    }

    // Trim the output to the desired size
    output &= (1 << numBits) - 1;
    return output;
  }

  /** Adds a branch outcome to the global history */
  void addHistory(bool isTaken) {
//    std::cout << "addHistory" << std::endl;
    for (int8_t i = size_ / 64; i >= 0; i--) {
      history_[i] <<= 1;
      if (i == 0) {
        history_[i] |= ((isTaken) ? 1 : 0);
      } else {
        history_[i] |= (((history_[i - 1] & ((uint64_t)1 << 63)) > 0) ? 1 : 0);
      }
    }
  }

  /** Updates the state of a branch that has already been added to the global
   * history at 'position', where position is 0-indexed and starts from the
   * least-significant bit.  I.e., to update the most recently added branch
   * outcome, position would be 0.
   * */
  void updateHistory(bool isTaken, uint64_t position) {
//    std::cout << "updateHistory" << std::endl;
    if (position < size_) {
      uint8_t vectIndex = position / 64;
      uint8_t bitIndex = position % 64;
      history_[vectIndex] ^= ((uint64_t)1 << bitIndex);
    }
  }

  /** removes the most recently added branch from the history */
  void rollBack() {
//    std::cout << "rollBack" << std::endl;
    for (uint8_t i = 0; i <= (size_ / 64); i++) {
      history_[i] >>= 1;
      if (i < (size_ / 64)) {
        history_[i] |= (((history_[i + 1] & 1) > 0) ? ((uint64_t)1 << 63) : 0);
      }
    }
  }

 private:
  /** The number of bits of branch history stored in this branch history */
  uint64_t size_;

  /** A vector containing this bits of the branch history.  The bits are
   * arranged such that the most recent branches are stored in uint64_t at
   * index 0 of the vector, then the next most recent at index 1 and so forth.
   * Within each uint64_t, the most recent branches are recorded int he
   * least-significant bits */
  std::vector<uint64_t> history_;
};

}