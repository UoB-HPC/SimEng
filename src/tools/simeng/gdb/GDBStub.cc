#include <sys/socket.h> // For socket functions
#include <netinet/in.h> // For sockaddr_in
#include <cstdlib> // For exit() and EXIT_FAILURE
#include <iostream> // For cout
#include <unistd.h> // For read
#include <string.h> // For memset, stoi
#include <regex> // For regex

#include "simeng/MemoryInterface.hh"
// src/include/simeng/models/emulation/Core.hh

// colour codes for pretty printing
#define RESET "\033[0m"
#define CYAN "\033[36m"
#define MAGENTA "\033[35m"

// converts bytes into 2 digit hex numbers
std::string byteToHex(uint8_t byte){

	std::string output = "00";
	
	int msb = byte / 16;
	int lsb = byte % 16;

	if(msb < 10) output[0] = msb + 48;
	else output[0] = msb + 87;

	if(lsb < 10) output[1] = lsb + 48;
	else output[1] = lsb + 87;

	return output;
}

// converts hex into uint64_t, used for converting GDB's memory address
uint64_t hexToInt(std::string hex){
	int base = 1;
	uint64_t output = 0;

	for(int i = hex.length() - 1; i >= 0; i--){
		if(hex[i] >= '0' && hex[i] <= '9') output += ((hex[i] - 48)* base);
		else if(hex[i] >= 'a' && hex[i] <= 'f') output += ((hex[i] - 87)* base);
		else(std::cout << "non hex characters in input string");
		base *= 16;
	}

	return output;
}

// converts uint64_t into RSP compliant hex, i.e. a series of 2 character hex bytes
std::string decToRSP(uint64_t dec){
	std::string output = "";
	if(dec == 0) output = "00";
	
	while(dec != 0){
		int temp = dec % 16;
		if(temp < 10) output += temp + 48;
		else output += temp + 87;

		dec = dec / 16;
	}

	if(output.length() % 2 == 1) output += '0';

	for(int i = 0; i < output.length(); i += 2){
		std::swap(output[i], output[i+1]);
	}
	return output;
}

// computes a RSP compliant checksum from a packet (sum of chars % 256, in a 2 digit hex)
std::string computeChecksum(std::string packet){
	std::string output;
	
	int decimalChecksum = 0;
	for(char c : packet) decimalChecksum += c;
	decimalChecksum = decimalChecksum % 256;

	output = byteToHex(decimalChecksum);

	return output;
}

// adds RSP compliant start and end characters, and a checksum
std::string generateReply(std::string packet){
	std::string output = "$" + packet + "#" + computeChecksum(packet);
	
	return output;
}

// reads all registers from SimEng and returns an RSP compliant string (1 byte at a time, in 2 digit hexes)
std::string handleReadRegisters(){
	
	std::array<std::array<uint8_t, 8>, 32> registers;
	for(int i = 0; i < 32; i++) for(uint8_t byte : registers[i]) byte = 0;

	// TODO replace this loop with reading SimEng registers (bytewise) and converting into hex (little endian wut ?)
	for(int i = 0; i < registers.size(); i++) registers[i][0] = uint8_t(i);

	std::string output = "";
	for(int i = 0; i < registers.size(); i++){
		registers[i][0] = i; // LSByte = incremental
		for(int j = 1; j < 8; j++) registers[i][j] = 0; //initialising rest of hex to zero

		for(uint8_t byte : registers[i]) {
			output += byteToHex(byte);
		}
	}
	for(int i = 0; i < 16; i++) output += "0"; // pc
	for(int i = 0; i < 8; i++) output += "0"; // cpsr
	return output;
}

// reads a single register and returns an RSP compliant string
std::string handleReadSingleRegister(std::string register){
	
	// TODO: read register from SimEng (register name is in hex) and respond in RSP compliant hex
	
	return "0000000000000000";
}

// reads a SimEng memory location and returns an RSP compliant string
std::string handleReadMemory(std::string address, std::string length, simeng::MemoryInterface& dataMemory){

	simeng::MemoryAccessTarget memoryAccessTarget = simeng::MemoryAccessTarget();

	memoryAccessTarget.address = hexToInt(address);
	memoryAccessTarget.size = std::stoi(length);

	dataMemory.requestRead(memoryAccessTarget);
	uint64_t value = dataMemory.getCompletedReads()[0].data.get<uint32_t>();
	dataMemory.clearCompletedReads();

	std::cout << "Value retrieved from memory: " << value << std::endl;

	std::string output = decToRSP(value);

	return output;
}

// creates a socket and listens on a port provided by an argument, or 2424 by default
// socket handling code taken from  https://ncona.com/2019/04/building-a-simple-server-with-cpp/
int openSocket(int port){
	
	// Create a socket (IPv4, TCP)
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		std::cout << "Failed to create socket. errno: " << errno << std::endl;
		exit(EXIT_FAILURE);
	}

	sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = INADDR_ANY;
	sockaddr.sin_port = htons(port); // htons is necessary to convert a number to
									// network byte order
	if (bind(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {
		std::cout << "Failed to bind to port " << port << ". errno: " << errno << std::endl;
		exit(EXIT_FAILURE);
	} else{
		std::cout << "Started listening on port " << port << std::endl;
	}

	// Start listening. Hold at most 10 connections in the queue
	if (listen(sockfd, 10) < 0) {
		std::cout << "Failed to listen on socket. errno: " << errno << std::endl;
		exit(EXIT_FAILURE);
	}

	// Grab a connection from the queue
	auto addrlen = sizeof(sockaddr);
	int connection = accept(sockfd, (struct sockaddr*)&sockaddr, (socklen_t*)&addrlen);
	if (connection < 0) {
		std::cout << "Failed to grab connection. errno: " << errno << std::endl;
		exit(EXIT_FAILURE);
	}

	return connection;
}

int runGDBStub(simeng::MemoryInterface& dataMemory) {

	int connection = openSocket(2425);

	char buffer[10000];

	while(true){
		auto bytesRead = read(connection, buffer, 10000);
		
		// '+' is an acknowledgement of successful receipt of message from the server
		// TODO: handle '-', no acknowledgement
		std::regex ack_regex("^\\+.*");

		// First parentheses = package, second = checksum
		std::regex packet_regex("^\\$([^#]*)#([0-9a-f]{2})");
		std::smatch packet_match;
		std::string bufferString = buffer;
		
		if(regex_match(bufferString, ack_regex)){
			std::cout << MAGENTA;
			std::cout << "<- Message Acknowledged" << std::endl;
		} else if(regex_match(bufferString, packet_match, packet_regex)){
			
			std::cout << CYAN;
			std::string packet = packet_match[1].str();
			if(packet_match.size() == 3) std::cout << "<- Received: " << packet << std::endl;
			else std::cout << "<- Unknown message" << std::endl; // TODO: take action

			std::string checksum = packet_match[2].str();
			std::string expected = computeChecksum(packet);

			if(checksum == expected) std::cout << "<- Checksum passed\n";
			else{
				std::cout << "<- Checksum failed\n"; // TODO: take action
				std::cout << "Expected checksum: " << expected << ", but received: " << checksum << std::endl; 
			}
			std::cout << MAGENTA;

			std::regex qSupported_regex("^qSupported:(.*)");
			std::smatch qSupported_match;

			std::string response = "+"; // acknowledgement

			if(packet == "?"){ // reason for halting
				response += generateReply("S05");
			} else if(packet == "g"){ // read registers
				std::string registers = handleReadRegisters();
				response += generateReply(registers);
			} else if(packet[0] == 'p'){ // read single register
				std::regex reg_regex("^m([0-9a-f]*)");
				std::smatch reg_match;
				regex_match(packet, reg_match, reg_regex);
				std::string registerValue = handleReadSingleRegister(reg_match[1]);
				response += generateReply(registerValue);
			} else if(packet[0] == 'm'){ // read memory
				std::regex mem_regex("^m([0-9a-f]*),([0-9a-f]*)");
				std::smatch mem_match;
				regex_match(packet, mem_match, mem_regex);
				std::string memoryValue = handleReadMemory(mem_match[1], mem_match[2], dataMemory);
				response += generateReply(memoryValue);
			} else if(packet[0] == 'M'){ // write memory
				response += generateReply("OK");
			} else if(packet[0] == 'G'){ // write registers
				response += generateReply("OK");
			} else{
				std::cout << "Packet not supported\n";
				response += generateReply("");
			}

			std::cout << "-> Sending: " << response << std::endl;
			send(connection, response.c_str(), response.size(), 0);

		}

		memset(buffer, 0, sizeof(buffer));
		std::cout << RESET;

	}
}