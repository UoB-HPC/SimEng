#pragma once

#include <iostream>
#include <sstream>
#include <string>

#include "framework/context.hh"

/**
 * Substitution failure is not an error (SFINAE) refers to a
 * situation in C++ where an invalid substitution of template parameters is not
 * in itself an error.
 * https://en.cppreference.com/w/cpp/language/sfinae
 */

/** Static class which exposes methods to color strings. */
class Formatter {
 private:
  /**
   * Genric method which takes in a color string and a target string, and
   * applies the color to the target string.
   */
  static std::ostringstream colour(std::string str, std::string tcolour) {
    std::ostringstream ss;
    ss << tcolour << str << reset();
    return ss;
  }
  /**
   * Reset the color such that characters following colored characters don't
   * inherit color.
   */
  static std::string reset() { return "\033[00m"; }

 public:
  /** Method which returns a blue string. */
  static std::string blue(std::string str) {
    return colour(str, "\033[34m").str();
  }
  /** Method which returns a grey string. */
  static std::string grey(std::string str) {
    return colour(str, "\033[30m").str();
  }
  /** Method which returns a bright green string. */
  static std::string bright_green(std::string str) {
    return colour(str, "\033[92m").str();
  }
  /** Method which returns a bright red string. */
  static std::string bright_red(std::string str) {
    return colour(str, "\033[91m").str();
  }
  /** Method which returns a bright grey string. */
  static std::string bright_grey(std::string str) {
    return colour(str, "\033[90m").str();
  }
  /** Method which returns a bold string. */
  static std::string bold(std::string str) {
    std::ostringstream ss;
    ss << "\033[1m" << str << reset();
    return ss.str();
  }
  /** Method which returns a bold bright green string. */
  static std::string bold_bright_green(std::string str) {
    return bold(bright_green(str));
  };
  /** Method which returns a bold grey string. */
  static std::string bold_grey(std::string str) { return bold(grey(str)); };
  /** Method which returns a bold bright grey string. */
  static std::string bold_bright_grey(std::string str) {
    return bold(bright_grey(str));
  }
  /** Method which returns a bold blue string. */
  static std::string bold_blue(std::string str) { return bold(blue(str)); };
  /** Method which returns a bold bright red string. */
  static std::string bold_bright_red(std::string str) {
    return bold(bright_red(str));
  };
};

/**
 * Output class which implements string building and output methods. This class
 * is also used capture the stdout of logic running inside a TEST_CASE.
 */
class Output {
 private:
  /** buffer used to capture stdout. */
  std::ostringstream buffer_;
  /** reference to the actual stdout stream which outputs to the terminal. */
  std::streambuf* prevcoutbuf_;
  /** default indent value set for all string builders and output methods. */
  int indent_ = 0;
  /** This method return an indent string. */
  auto indent(uint32_t t) const {
    std::string ss = "";
    for (uint32_t x = 0; x < t; x++) {
      ss += ' ';
    }
    return ss;
  }

 public:
  /**
   * Type trait SFINAE expression which filters the template argument to only
   * allow fundamental types and strings to pass argument types.
   */
  template <typename... Ts>
  using IsAllowed = typename std::enable_if<std::conjunction<
      std::disjunction<std::is_same<char*, typename std::decay_t<Ts>>,
                       std::is_same<const char*, typename std::decay_t<Ts>>,
                       std::is_same<std::string, typename std::decay_t<Ts>>,
                       std::is_fundamental<Ts>>...>::value>::type;

  template <typename... Ts, typename = IsAllowed<Ts...>,
            std::size_t N = sizeof...(Ts)>
  /** output method which outputs any fundamental type arguments to stdout. */
  void output(std::string delimiter, int ind, Ts const&... xs) const {
    std::ostringstream oss;
    ([&] { oss << xs << delimiter; }(), ...);

    std::string str = oss.str();
    std::string builder = "";
    for (size_t x = 0; x < oss.str().size(); x++) {
      if (str[x] == '\n') {
        std::cout << indent(ind + indent_) << builder << std::endl;
        builder = "";
      } else {
        builder += str[x];
      }
    }
    if (builder != "") {
      std::cout << indent(ind + indent_) << builder << std::endl;
    }
  }

  template <typename... Ts, typename = IsAllowed<Ts...>,
            std::size_t N = sizeof...(Ts)>
  /**
   * String builder method which builds a string out of any fundamental type
   * argumemts.
   */
  std::string strBuilder(std::string delimiter, Ts const&... xs) const {
    std::ostringstream oss;
    ([&] { oss << xs << delimiter; }(), ...);
    return oss.str();
  }

  /** Method which prints a passing test case given a TestContext. */
  void pass(TestContext* ctx) const {
    output(" ", 0, Formatter::bold_bright_green("[PASS]:"),
           ctx->getTestCaseName());
  };

  /** Method which prints a failing test case given a TestContext. */
  void fail(TestContext* ctx) const {
    output(" ", 0, Formatter::bold_bright_red("[FAIL]:"),
           ctx->getTestCaseName());
    output("", 4, Formatter::bold("Source: "), ctx->getTestCaseSrcFile(), ":",
           ctx->getTestCaseLineNum());
  };

  /** Method which prints a group name. */
  void group(std::string groupName) {
    output(" ", 0, Formatter::bold_blue("[TEST GROUP]:"),
           Formatter::bold(groupName));
  }

  /**
   * This method which captures the stdout, it replaces the default stream
   * buffer with ostringstream buffer enabling all calls to std::cout to be
   * captured in buffer_.
   */
  void captureStdCout() {
    buffer_ = std::ostringstream();
    prevcoutbuf_ = std::cout.rdbuf(buffer_.rdbuf());
  }

  /** This method prints the captured stdout. */
  void printCapturedStdCout(int indent = 0) const {
    std::string str = buffer_.str();
    if (str[str.size() - 1] == '\n') {
      str[str.size() - 1] = '\0';
    }
    if (str.size()) {
      output("", 0, Formatter::bold_bright_grey("Captured output: "));
      output("", indent, Formatter::grey(str));
    }
  }

  /**
   * This method resets the stream buffer of stdout so that it prints back to
   * the terminal.
   */
  void resetStdCoutBuffer() { std::cout.rdbuf(prevcoutbuf_); }

  /**
   * Method used to set default indent for any output or string building
   * methods.
   */
  void setIndent(int indent) { indent_ = indent; }
};