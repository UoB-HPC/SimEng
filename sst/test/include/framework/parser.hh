#pragma once
#include <iostream>
#include <map>
#include <string>
#include <vector>

struct ParsedMemRead {
  uint64_t reqId_;
  uint64_t startCycle_;
  uint64_t endCycle_;
  uint64_t data_;
  uint64_t numReqs_;
};

/**
 * Parser class used to parse captured stdout into meaninful and comparable
 * data.
 */
class Parser {
 private:
  /** Captured Stdout split into lines. */
  std::vector<std::string> splitStdout_;

  /** vector of ParsedMemReads. */
  std::vector<ParsedMemRead*> parsedMemReads_;

  /** vector of stdout lines having the SimEng:SSTDebug:OutputLine prefix. */
  std::vector<std::string> outputLines;

 public:
  Parser(std::string capturedStdOut) {
    splitStdout_ = splitStdoutIntoLines(capturedStdOut);
    parsedMemReads_ = parseOutput();
  };
  ~Parser(){};
  /** Returns the parsed stdout as ParsedMemReads. */
  std::vector<ParsedMemRead*> getParsedMemReads() { return parsedMemReads_; }

  /**
   * Returns a vector of stdout lines having the SimEng:SSTDebug:OutputLine
   * prefix.
   */
  std::vector<std::string> getOutputLines() { return outputLines; }

 private:
  /** This methiod parses the captured stdout */
  std::vector<ParsedMemRead*> parseOutput() {
    std::map<uint64_t, ParsedMemRead*> pmap;
    std::vector<ParsedMemRead*> out;
    for (size_t x = 0; x < splitStdout_.size(); x++) {
      if (splitStdout_[x].find("SSTSimEng:SSTDebug") == std::string::npos)
        continue;
      std::vector<std::string> splitStr = split(splitStdout_[x], "-");
      if (splitStr[0] == "[SSTSimEng:SSTDebug] MemRead") {
        uint64_t id = std::stoull(splitStr[3]);
        auto itr = pmap.find(id);
        if (itr != pmap.end()) {
          itr->second->endCycle_ = std::stoull(splitStr[5]);
          itr->second->data_ = std::stoull(splitStr[7]);
          out.push_back(itr->second);
        } else {
          ParsedMemRead* p = new ParsedMemRead();
          p->reqId_ = id;
          p->startCycle_ = std::stoull(splitStr[5]);
          p->numReqs_ = std::stoull(splitStr[7]);
          pmap.insert(std::pair<uint64_t, ParsedMemRead*>(id, p));
        }
      }
      if (splitStr[0] == "[SSTSimEng:SSTDebug] OutputLine") {
        std::string str = "";

        for (size_t y = 1; y < splitStr.size(); y++) {
          str += splitStr[y];
        }
        outputLines.push_back(str);
      }
    }
    return out;
  }

  /** This method splits capturedStdout into lines. */
  std::vector<std::string> splitStdoutIntoLines(std::string capturedStdout) {
    std::stringstream ss(capturedStdout);
    std::string line;
    std::vector<std::string> lines;
    bool start = false;

    while (std::getline(ss, line, '\n')) {
      if (!start) {
        if (line.find("[SimEng] Starting...") != std::string::npos) {
          start = true;
        }
      } else {
        if (line.find("Simulation complete. Finalising stats....") !=
            std::string::npos) {
          break;
        }
        lines.push_back(line);
      }
    }
    return lines;
  };

  /** This method split a string into a vector of strings given a delimiter. */
  std::vector<std::string> split(std::string s, std::string delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::string token;
    std::vector<std::string> res;

    while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
      token = s.substr(pos_start, pos_end - pos_start);
      pos_start = pos_end + delim_len;
      res.push_back(token);
    }

    res.push_back(s.substr(pos_start));
    return res;
  }
};