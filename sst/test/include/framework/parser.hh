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
};

class Parser {
 private:
  std::vector<std::string> splitStdout_;
  std::vector<ParsedMemRead*> parsedMemReads_;

 public:
  Parser(std::string capturedStdOut) {
    splitStdout_ = splitStdoutIntoLines(capturedStdOut);
    parsedMemReads_ = parseOutput();
  };
  ~Parser(){};
  std::vector<ParsedMemRead*> getParseMemReads() { return parsedMemReads_; }

 private:
  std::vector<ParsedMemRead*> parseOutput() {
    std::map<uint64_t, ParsedMemRead*> pmap;
    std::vector<ParsedMemRead*> out;
    for (int x = 0; x < splitStdout_.size(); x++) {
      if (splitStdout_[x].find("SimEng:SSTDebug") == std::string::npos)
        continue;
      std::vector<std::string> splitStr = split(splitStdout_[x], "-");
      if (splitStr[0] == "[SimEng:SSTDebug:MemRead]") {
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
          pmap.insert(std::pair<uint64_t, ParsedMemRead*>(id, p));
        }
      }
    }
    return out;
  }
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