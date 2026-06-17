#pragma once

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "simeng/version.hh"

namespace SST {

namespace SSTSimEng {

class Assembler {
 private:
  /** The flat binary produced by assembling the test source. */
  uint8_t* code_ = nullptr;

  /** The size of the assembled flat binary in bytes. */
  size_t codeSize_ = 0;

  /** Assemble test source to a flat binary for the given triple. */
  void assemble(const char* source, const char* triple);

 public:
  /** Constructor for Assembler class which takes in source code. */
  Assembler(std::string source);
  ~Assembler();

  /** Returns the assembled source as a char array. */
  char* getAssembledSource();

  /** Returns the size of the assembled source. */
  size_t getAssembledSourceSize();
};

}  // namespace SSTSimEng
}  // namespace SST