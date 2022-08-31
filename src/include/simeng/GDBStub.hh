#pragma once

#include <netinet/in.h>  // For sockaddr_in
#include <sys/socket.h>  // For socket functions
#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <regex>
#include <string>

#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/Core.hh"
#include "simeng/MemoryInterface.hh"

// colour codes for pretty printing
#define RESET "\033[0m"
#define CYAN "\033[36m"
#define GREEN "\033[32m"
#define RED "\033[31m"

namespace simeng {

/** A class that is a GDB server stub, managing communication between SimEng and
 * a GDB client that connects to it remotely, using GDB's Remote Serial Protocol
 * (RSP). This class is only compiled when the GDB_ENABLED build option is set.
 */
class GDBStub {
 public:
  /** Construct a GDBStub with pointers to a core and memory interface.  N.B.
   * There is currently only support for an emulation core and a
   * FlatMemoryInterface */
  GDBStub(simeng::Core& core, simeng::MemoryInterface& dataMemory);

  /** Run the GDBStub using the core and dataMemory properties.  This gives
   * control of the emulation core and hands it to a GDB client that connects to
   * the GDBStub via the provided port (2425 by default)*/
  int run();

 private:
  /** Convert a byte into a 2 digit hex value. */
  std::string byteToHex(uint8_t byte) const;

  /** Convert hex into uint64_t, used for converting GDB's memory address. */
  uint64_t hexToInt(std::string hex) const;

  /** Convert uint64_t into RSP compliant hex - a series of 8 hex bytes. */
  std::string decToRSP(uint64_t dec) const;

  /** Compute an RSP compliant checksum from a packet (sum of chars % 256, in a
   * 2 digit hex). */
  std::string computeChecksum(std::string packet) const;

  /** Add RSP compliant start and end characters, followed by a checksum. */
  std::string generateReply(std::string packet) const;
  ;

  /** Read all registers from the core and return an RSP compliant string. */
  std::string handleReadRegisters() const;

  /** Read a single register and return an RSP compliant string. */
  std::string handleReadSingleRegister(std::string registerName) const;

  /** Read `length` number of bytes from memory location `hexAddress` and return
   * an RSP compliant string. */
  std::string handleReadMemory(std::string hexAddress,
                               std::string length) const;

  /** Create a breakpoint at the provided address. */
  void handleCreateBreakpoint(std::string type, std::string address);

  /** Remove breakpoints matching the provided address. */
  void handleRemoveBreakpoint(std::string type, std::string address);

  /** Continue execution until the next breakpoint; does nothing if there are no
   * breakpoints. */
  std::string handleContinue();

  /** Create a socket and listen on the port number provided.
   * Socket handling code taken from:
   * https://ncona.com/2019/04/building-a-simple-server-with-cpp/. */
  int openSocket(int port) const;

  /** Boolean for if the runtime -v verbose flag has been set. */
  bool verbose_ = 0;

  /** The core used for the simulation.  Currently only supports the
   * emulation core*/
  simeng::Core& core_;

  /** The memory interface used for the simulation.  Currently only supports a
   * FlatMemoryInterface */
  simeng::MemoryInterface& dataMemory_;

  /** A set of breakpoints provided by the GDB client. */
  std::vector<std::string> breakpoints_;
};
}  // namespace simeng