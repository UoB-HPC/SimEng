#include "simeng/GDBStub.hh"

namespace simeng {

GDBStub::GDBStub(simeng::Core& core, simeng::MemoryInterface& dataMemory)
    : core_(core), dataMemory_(dataMemory) {}

int GDBStub::run() {
  // verbose_ = 1; // uncomment this if you'd like the GDBStub to run verbosely

  int connection = openSocket(2424);  // change this if the port is blocked

  std::cout << "Connection to GDB client established, debugging in progress"
            << std::endl
            << std::endl;

  char buffer[10000];

  while (true) {
    read(connection, buffer, 10000);

    // '+' is an acknowledgement of successful receipt of message
    // TODO: handle '-', no acknowledgement
    std::regex ack_regex("^\\+.*");

    // First parentheses = package, second = checksum
    std::regex packet_regex("^\\$([^#]*)#([0-9a-f]{2})");
    std::smatch packet_match;
    std::string bufferString = buffer;

    if (regex_match(bufferString, ack_regex)) {
      if (verbose_)
        std::cout << CYAN << "<- Received message acknowledgement" << std::endl
                  << RESET;
    } else if (regex_match(bufferString, packet_match, packet_regex)) {
      std::string packet = packet_match[1].str();
      if (verbose_) {
        std::cout << CYAN;
        if (packet_match.size() == 3)
          std::cout << "<- Received packet: " << packet << std::endl;
        else
          std::cout << RED << "<- Unknown message"
                    << std::endl;  // TODO: take action
        std::cout << RESET;
      }
      std::string checksum = packet_match[2].str();
      std::string expected = computeChecksum(packet);
      if (verbose_ && checksum != expected) {
        std::cout << RED << "   Checksum failed\n"
                  << "   Expected checksum: " << expected
                  << "   , but received: " << checksum << std::endl
                  << RESET;
        // TODO: take action
      }

      std::regex qSupported_regex("^qSupported:(.*)");
      std::smatch qSupported_match;

      std::string response = "+";  // acknowledgement

      if (packet == "?") {  // reason for halting
        response += generateReply("S05");
      } else if (packet == "s") {  // step one instruction
        core_.tick();
        dataMemory_.tick();
        response += generateReply("S05");
      } else if (packet == "c") {  // continue until next breakpoint
        std::string message = handleContinue();
        response += generateReply(message);
      } else if (packet == "g") {  // read registers
        std::string registers = handleReadRegisters();
        response += generateReply(registers);
      } else if (packet[0] == 'p') {  // read single register
        std::regex reg_regex("^p([0-9a-f]*)");
        std::smatch reg_match;
        regex_match(packet, reg_match, reg_regex);
        std::string registerValue = handleReadSingleRegister(reg_match[1]);
        response += generateReply(registerValue);
      } else if (packet[0] == 'm') {  // read memory
        std::regex mem_regex("^m([0-9a-f]*),([0-9a-f]*)");
        std::smatch mem_match;
        regex_match(packet, mem_match, mem_regex);
        std::string memoryValue = handleReadMemory(mem_match[1], mem_match[2]);
        response += generateReply(memoryValue);
      } else if (packet[0] == 'Z' ||
                 packet[0] == 'z') {  // create/remove breakpoint
        std::regex break_regex(
            "^([zZ])([0-4]),([0-9a-f]+),([0-9a-f]+)");  // format:
                                                        // z/Z,type,address,kind
        std::smatch break_match;
        regex_match(packet, break_match, break_regex);
        std::string type = break_match[2];
        std::string address = break_match[3];
        // std::string kind = break_match[4]; // kind not used
        if (packet[0] == 'Z')
          handleCreateBreakpoint(type, address);
        else
          handleRemoveBreakpoint(type, address);
        response += generateReply("OK");
      } else if (packet[0] == 'M') {  // write memory
        response += generateReply("OK");
      } else if (packet[0] == 'G') {  // write registers
        response += generateReply("OK");
      } else {
        if (verbose_) std::cout << RED << "   Packet not supported\n" << RESET;
        response += generateReply("");
      }

      if (verbose_)
        std::cout << GREEN << "-> Sending: " << response << RESET << std::endl;
      send(connection, response.c_str(), response.size(), 0);
    }

    memset(buffer, 0, sizeof(buffer));
  }
}

std::string GDBStub::byteToHex(uint8_t byte) const {
  std::string output = "00";

  int msb = byte / 16;
  int lsb = byte % 16;

  if (msb < 10)
    output[0] = msb + 48;
  else
    output[0] = msb + 87;

  if (lsb < 10)
    output[1] = lsb + 48;
  else
    output[1] = lsb + 87;

  return output;
}

uint64_t GDBStub::hexToInt(std::string hex) const {
  int base = 1;
  uint64_t output = 0;

  for (int i = hex.length() - 1; i >= 0; i--) {
    if (hex[i] >= '0' && hex[i] <= '9')
      output += ((hex[i] - 48) * base);
    else if (hex[i] >= 'a' && hex[i] <= 'f')
      output += ((hex[i] - 87) * base);
    else
      std::cout << RED << "non hex characters in input string" << RESET;
    base *= 16;
  }

  return output;
}

std::string GDBStub::decToRSP(uint64_t dec) const {
  std::string output;

  while (dec != 0) {
    int temp = dec % 16;
    if (temp < 10)
      output += temp + 48;
    else
      output += temp + 87;

    dec = dec / 16;
  }

  output = output + std::string(16 - output.length(), '0');

  for (uint i = 0; i < output.length(); i += 2) {
    std::swap(output[i], output[i + 1]);
  }

  return output;
}

std::string GDBStub::computeChecksum(std::string packet) const {
  std::string output;

  int decimalChecksum = 0;
  for (char c : packet) decimalChecksum += c;
  decimalChecksum = decimalChecksum % 256;

  output = byteToHex(decimalChecksum);

  return output;
}

std::string GDBStub::generateReply(std::string packet) const {
  std::string output = "$" + packet + "#" + computeChecksum(packet);

  return output;
}

std::string GDBStub::handleReadRegisters() const {
  simeng::ArchitecturalRegisterFileSet registers =
      core_.getArchitecturalRegisterFileSet();
  std::string output = "";

  for (uint16_t i = 0; i < 32;
       i++) {  // general purpose registers 0-31, 31 = stack pointer
    uint64_t value = registers.get({0, i}).get<uint64_t>();
    output += decToRSP(value);
  }

  output += decToRSP(core_.getProgramCounter());  // program counter

  output += byteToHex(
      registers.get({3, 0}).get<uint8_t>());  // NZCV (first 4 bits of cpsr)

  output += "000000";  // rest of cpsr, unneeded

  return output;
}

std::string GDBStub::handleReadSingleRegister(std::string registerName) const {
  uint16_t registerNumber = hexToInt(registerName);
  uint64_t value = core_.getArchitecturalRegisterFileSet()
                       .get({0, registerNumber})
                       .get<uint64_t>();

  return decToRSP(value);
}

std::string GDBStub::handleReadMemory(std::string hexAddress,
                                      std::string length) const {
  int numberOfBytes = std::stoi(length);
  uint64_t intAddress = hexToInt(hexAddress);

  char* memoryPointer = dataMemory_.getMemoryPointer();
  const char* ptr = memoryPointer + intAddress;
  uint8_t dest[numberOfBytes];

  if (verbose_)
    std::cout << "   Reading " << numberOfBytes << " bytes from memory address "
              << intAddress << std::endl;

  memcpy(dest, ptr, numberOfBytes);

  std::string output;
  for (uint8_t byte : dest) output += byteToHex(byte);

  return output;
}

void GDBStub::handleCreateBreakpoint(std::string type, std::string address) {
  if (stoi(type) > 1)
    std::cout << RED << "   Watchpoints not supported, no breakpoint created\n"
              << RESET;

  breakpoints_.push_back(address);
  if (verbose_)
    std::cout << "   Breakpoint created at address 0x" << address << std::endl;
}

void GDBStub::handleRemoveBreakpoint(std::string type, std::string address) {
  if (stoi(type) > 1)
    std::cout << RED << "   Watchpoints not supported, no breakpoint removed\n"
              << RESET;

  for (uint i = 0; i < breakpoints_.size(); i++) {
    if (breakpoints_[i] == address)
      breakpoints_.erase(breakpoints_.begin() + i);
  }
  if (verbose_)
    std::cout << "   Breakpoint(s) removed at address 0x" << address
              << std::endl;
}

std::string GDBStub::handleContinue() {
  if (breakpoints_.size() == 0) return "";

  bool hitBreakpoint = 0;

  while (!hitBreakpoint) {
    core_.tick();
    dataMemory_.tick();
    for (std::string breakpoint : breakpoints_) {
      if (hexToInt(breakpoint) == core_.getProgramCounter()) hitBreakpoint = 1;
    }
  }

  return "S05";
}

int GDBStub::openSocket(int port) const {
  // Create a socket (IPv4, TCP)
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    std::cout << RED << "   Failed to create socket. errno: " << errno
              << std::endl
              << RESET;
    exit(EXIT_FAILURE);
  }

  sockaddr_in sockaddr;
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = INADDR_ANY;
  sockaddr.sin_port = htons(port);  // htons is necessary to convert a number to
                                    // network byte order
  if (bind(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {
    std::cout << RED << "   Failed to bind to port " << port
              << ". errno: " << errno << std::endl
              << RESET;
    exit(EXIT_FAILURE);
  } else {
    std::cout << "Started listening on port " << port << std::endl;
  }

  // Start listening. Hold at most 10 connections in the queue
  if (listen(sockfd, 10) < 0) {
    std::cout << RED << "   Failed to listen on socket. errno: " << errno
              << std::endl
              << RESET;
    exit(EXIT_FAILURE);
  }

  // Grab a connection from the queue
  auto addrlen = sizeof(sockaddr);
  int connection =
      accept(sockfd, (struct sockaddr*)&sockaddr, (socklen_t*)&addrlen);
  if (connection < 0) {
    std::cout << RED << "   Failed to grab connection. errno: " << errno
              << std::endl
              << RESET;
    exit(EXIT_FAILURE);
  }

  return connection;
}

}  // namespace simeng