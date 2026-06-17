#pragma once

#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "framework/context.hh"
#include "framework/runner.hh"
#include "framework/uid.hh"

/**
 * The Registry class is used register Factory(s) which are able
 * to create Runner(s) associated with TEST_GROUP(s). Registry is a singleton
 * and can be only be instantiated once.
 */
class Registry {
 public:
  using Factory = std::function<std::unique_ptr<Runner>()>;
  using RegistryMap = std::map<std::string, std::vector<Factory>>;

  /** Method creates and returns the singleton instance of Registry. */
  static Registry* getInstance() {
    /** Static instance of the singleton Registry class. */
    static Registry* instance_;
    if (instance_ == NULL) {
      instance_ = new Registry();
    }
    return instance_;
  }

  /**
   * This method returns derived instance of classes extending the Runner class
   * as polymorphic parent instances i.e the make_unique function calls the
   * constructor of classes extending the Group class and returns them as
   * polymorphic Runner(s) i.e std::make_unique<T extends Group>()
   */
  template <typename T>
  static std::unique_ptr<Runner> createDerived() {
    return std::make_unique<T>();
  }

  /**
   * This method registers a Factory responsible for creating polymorphic
   * Runner(s) instances of classes extending the Group class.
   */
  static bool registerGroup(std::string fname, uint64_t line, std::string gname,
                            Factory f) {
    UidRegistry::validateGroupName(gname, fname, line);
    return addRunner(fname, f);
  };

  /**
   * This method returns the singleton instance of RegistryMap used to store
   * all Factory(s).
   */
  static RegistryMap* getMap() {
    /** Static instance of the map used to store all Factory(s). */
    static RegistryMap* map;
    if (!map) {
      map = new RegistryMap;
    }
    return map;
  }

 private:
  Registry(){};
  /** Method used to add Factory(s) to the RegistryMap. */
  static bool addRunner(std::string fname, Factory f) {
    auto rMap = getMap();
    auto itr = rMap->find(fname);
    if (itr == rMap->end()) {
      std::vector<Factory> v;
      v.push_back(f);
      rMap->insert(std::pair<std::string, std::vector<Factory>>(fname, v));
      return true;
    }
    itr->second.push_back(f);
    return true;
  }
};

/**
 * This macro registers Factory(s) of dervied instance of Group(s) into the
 * Registry.This macro is automatically called inside the TEST_GROUP macro.
 */
#define REGISTER(X, gname, cname) \
  const bool X::registered_ =     \
      Registry::registerGroup(cname, __LINE__, gname, X::factory());

/**
 * This macro attaches a Factory, responsible for instantiating a polymorphic
 * instance of any class extending Group, to any classes extending the Group
 * class. This macro is automatically called in the TEST_GROUP macro.
 */
#define FACTORY(X)                                                       \
  static Registry::Factory factory() {                                   \
    Registry::Factory f = []() { return Registry::createDerived<X>(); }; \
    return f;                                                            \
  }
