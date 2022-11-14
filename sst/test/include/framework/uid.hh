#pragma once

#include <memory>
#include <set>
#include <string>

#include "framework/output.hh"
/**
 * This Singleton class ensures that all TEST_GROUP(s) have unique names, and
 * all TEST_CASE(s) in a TEST_GROUP have unique names.
 */
class UidRegistry {
 private:
  UidRegistry(){};
  /** This method checks if an id is unique. */
  static bool isUnique(std::string id) {
    std::unique_ptr<std::set<std::string>>& uidReg = getUidReg();
    auto itr = uidReg->find(id);
    if (itr != uidReg->end()) {
      return false;
    }
    uidReg->insert(id);
    return true;
  }
  /** This method returns the singleton reference to the UidRegistry class. */
  static std::unique_ptr<std::set<std::string>>& getUidReg() {
    static std::unique_ptr<std::set<std::string>> set;
    if (set == nullptr) {
      set = std::unique_ptr<std::set<std::string>>(new std::set<std::string>());
    }
    return set;
  }

 public:
  /** This method validates the uniqueness of a TEST_GROUP name.*/
  static void validateGroupName(std::string gname, std::string fname,
                                uint64_t line) {
    Output output;
    if (!isUnique(gname)) {
      output.output(" ", 0,
                    Formatter::bold_bright_red("Duplicate TestGroup name:"),
                    Formatter::bold("\"" + gname + "\""));
      output.output("", 4, Formatter::bold("Source: "), fname, ':', line);
      exit(EXIT_FAILURE);
    }
  }
  /**
   * This method validates the uniqueness of the TEST_CASE name within a
   * TEST_GROUP.
   */
  static void validateTestName(std::string gname, std::string tname,
                               std::string fname, uint64_t line) {
    Output output;
    std::string uid = gname + '.' + tname;
    if (!isUnique(uid)) {
      output.output(
          " ", 0,
          Formatter::bold_bright_red("Duplicate TestCase name in TestGroup:"),
          Formatter::bold("\"" + gname + "\""), "-",
          Formatter::bold("\"" + tname + "\""));
      output.output("", 4, Formatter::bold("Source: "), fname, ':', line);
      exit(EXIT_FAILURE);
    }
  }
};