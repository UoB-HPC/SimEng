#pragma once

#include <stdexcept>
#include <string>
#include <type_traits>
/**
 * Substitution failure is not an error (SFINAE) refers to a
 * situation in C++ where an invalid substitution of template parameters is not
 * in itself an error.
 * https://en.cppreference.com/w/cpp/language/sfinae
 */

/**
 * SFINAE type trait which only allows the template arguments to be a
 * fundamental type.
 */
template <typename T>
using IsFundamentalType =
    typename std::enable_if<std::is_fundamental_v<T>, T>::type;

/**
 * SFINAE type trait which checks if the template argument is char*, const char*
 * or std::string.
 */
template <typename... Ts>
using IsString = typename std::enable_if<std::conjunction<std::disjunction<
    std::is_same<char*, typename std::decay_t<Ts>>,
    std::is_same<const char*, typename std::decay_t<Ts>>,
    std::is_same<std::string, typename std::decay_t<Ts>>>...>::value>::type;

/**
 * This struct represents the evaluation of an expression and all details
 * related to it.
 */
struct ExprEval {
  /** The result of the evaluation. */
  const bool result_;
  /** Depicts if the expression was binary or unary. */
  const bool is_binary_;
  /** The expression as a string. */
  std::string exprString_;
  /** The line on which the source of the expression is written. */
  uint64_t exprLineNum_;
  ExprEval() : result_(0), is_binary_(0), exprString_(""), exprLineNum_(0){};
  ExprEval(bool result, bool is_binary, std::string exprString,
           uint64_t exprLineNum)
      : result_(result),
        is_binary_(is_binary),
        exprString_(exprString),
        exprLineNum_(exprLineNum){};
  ExprEval(bool result, bool is_binary)
      : result_(result),
        is_binary_(is_binary),
        exprString_(""),
        exprLineNum_(0){};
};

/**
 * This class represent an expression that can be evaluated to boolean a result.
 */
class BaseExpr {
 public:
  /**
   * This is a virtual method which converts a Unary expression represented by a
   * class extending BaseExpr into ExprEval.
   */
  virtual auto makeUnaryExprEval() -> ExprEval {
    return ExprEval{false, false, "", 0};
  }
};

/**
 * This class represent the LHS of any expression which can be evaluated to a
 * boolean result. For Unary expression the value evaluated is still stored
 * as LHS, however during evaluation the makeUnaryExprEval method uses the
 * static_cast method for evaluation.
 */
template <typename Lhs, typename = IsFundamentalType<Lhs>>
class LhsExpr : public BaseExpr {
 private:
  /** The left hand side of an expression. */
  Lhs lhs_;

 public:
  explicit LhsExpr(Lhs lhs) : lhs_(lhs){};

  /**
   * This operator overload enables the execution of the 'greater than'
   * operation on the RHS value without having to define its template type. The
   * templated type is filtered by a SFINAE type trait which only allows
   * template argument to be a fundamental type.
   */
  template <typename Rhs, typename = IsFundamentalType<Rhs>>
  auto operator>(Rhs const& rhs) -> ExprEval {
    return ExprEval{static_cast<bool>(lhs_ > rhs), true};
  };

  /**
   * This operator overload enables the execution of the 'less than' operation
   * on the RHS value without having to define its template type. The templated
   * type is filtered by a SFINAE type trait which only allows the template
   * argument to be a fundamental type.
   */
  template <typename Rhs, typename = IsFundamentalType<Rhs>>
  auto operator<(Rhs const& rhs) -> ExprEval {
    return ExprEval{static_cast<bool>(lhs_ < rhs), true};
  };

  /**
   * This operator overload enables the execution of the 'greater than or
   * equal' operation on the RHS value without having to define its template
   * type. The templated type is filtered by a SFINAE type trait which only
   * allows the template argument to be a fundamental type.
   */
  template <typename Rhs, typename = IsFundamentalType<Rhs>>
  auto operator>=(Rhs const& rhs) -> ExprEval {
    return ExprEval{static_cast<bool>(lhs_ >= rhs), true};
  };

  /**
   * This operator overload enables the execution of the 'less than or equal'
   * operation on the RHS value without having to define its template type. The
   * templated type is filtered by a SFINAE type trait which only allows the
   * template argument to be a fundamental type.
   */
  template <typename Rhs, typename = IsFundamentalType<Rhs>>
  auto operator<=(Rhs const& rhs) -> ExprEval {
    return ExprEval{static_cast<bool>(lhs_ <= rhs), true};
  };

  /**
   * This operator overload enables the execution of the 'equals' operation on
   * the RHS value without having to define its template type. The templated
   * type is filtered by a SFINAE type trait which only allows the template
   * argument to be a fundamental type.
   */
  template <typename Rhs, typename = IsFundamentalType<Rhs>>
  auto operator==(Rhs const& rhs) -> ExprEval {
    return ExprEval{static_cast<bool>(lhs_ == rhs), true};
  };

  /**
   * This operator overload enables the execution of the 'not equals' operation
   * on the RHS value without having to define its template type. The templated
   * type is filtered by a SFINAE type trait which only allows the template
   * argument to be a fundamental type.
   */
  template <typename Rhs, typename = IsFundamentalType<Rhs>>
  auto operator!=(Rhs const& rhs) -> ExprEval {
    return ExprEval{static_cast<bool>(lhs_ != rhs), true};
  };

  /** Overloaded instance of makeUnaryExprEval from BaseExpr. */
  auto makeUnaryExprEval() -> ExprEval {
    return ExprEval{static_cast<bool>(lhs_), false};
  }
};

/**
 * ExprBuilder struct exposes a operator which is used to instantiate an
 * LhsExpr of type T without having to explictly define the template argument.
 */
struct ExprBuilder {
  template <typename T, typename = IsFundamentalType<T>>
  /**
   * This operator invocation instantiates the LhsExpr with only fundamental
   * types.
   */
  auto operator<<(T const& lhs) -> LhsExpr<T> {
    return LhsExpr<T>(lhs);
  }
  /**
   * This overloaded operator throws an exception if invoked with a string.
   */
  template <typename Ts, typename = IsString<Ts>>
  auto operator<<(Ts const& arg) -> bool {
    throw std::invalid_argument(
        "String comparisons should be done with STR macros.");
    return false;
  }
};

/**
 * This class represent the LHS and RHS of any expression containing strings
 * which can be evaluated to a boolean result.
 */
class StrExpr : public BaseExpr {
  std::string lhs_;
  std::string rhs_;

 public:
  explicit StrExpr(std::string lhs) : lhs_(lhs){};

  /**
   * This operator overload enables initialisation of rhs without having to
   * define the template argument explicitly. The templated argument is filtered
   * by the IsString SFINAE type trait.
   */
  template <typename T, typename = IsString<T>>
  auto operator<<(T const& arg) -> StrExpr {
    rhs_ = std::string(arg);
    return *(this);
  }
  /**
   * This method checks if the LHS string is equal to the RHS string and returns
   * the result as an ExprEval struct.
   */
  auto compareEqual() -> ExprEval {
    return ExprEval{!static_cast<bool>(lhs_.compare(rhs_)), true};
  }
  /**
   * This method checks if the LHS string is not equal to the RHS string and
   * returns the result as an ExprEval struct.
   */
  auto compareNotEqual() -> ExprEval {
    return ExprEval{static_cast<bool>(lhs_.compare(rhs_)), true};
  }
  /**
   * This method checks if the LHS string starts with the RHS string and returns
   * the result as an ExprEval struct.
   */
  auto startWith() -> ExprEval {
    auto pos = lhs_.find(rhs_);
    return ExprEval{pos == 0, true};
  }
  /**
   * This method checks if the LHS string contains the RHS string and returns
   * the result as an ExprEval struct.
   */
  auto contains() -> ExprEval {
    auto pos = lhs_.find(rhs_);
    return ExprEval{pos != std::string::npos, true};
  }
  /**
   * This method throws an error if StrExpr is ever treated as a Unary
   * expression.
   */
  auto makeUnaryExprEval() -> ExprEval {
    throw std::domain_error("String Expressions cannot be Unary");
  }
};

/**
 * StrExprBuilder struct exposes a operator which is used to instantiate an
 * StrExpr of type T (filtered by the SFINAE expression) without having to
 * explicitly define the template argument of type char*, const char* or
 * std::string.
 */
struct StrExprBuilder {
  template <typename T, typename = IsString<T>>
  auto operator<<(T const& arg) -> StrExpr {
    std::string str = std::string(arg);
    return StrExpr{str};
  };
};
