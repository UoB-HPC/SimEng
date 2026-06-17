#pragma once

#include "framework/expression.hh"
#include "framework/handlers.hh"
#include "framework/macros/util.hh"

// This MACRO defines the source code each expression expands into. This MACRO
// also adds the line number on which this MACRO is defined in the source code.
#define GENERIC_EXPECT_WITH_LINE(A, OP, B, line, SRC)      \
  {                                                        \
    ExpressionHandler handler = ExpressionHandler();       \
    handler.handleExpression(ExprBuilder() << A OP B, SRC, \
                             static_cast<uint64_t>(line)); \
  }

// This MACRO defines the source code each String expression expands into. This
// MACRO also adds the line number on which this MACRO is defined in the source
// code.
#define GENERIC_STR_MATCHER_WITH_LINE(A, OP, B, line, SRC)         \
  {                                                                \
    ExpressionHandler handler = ExpressionHandler();               \
    handler.handleExpression((StrExprBuilder() << A << B).OP, SRC, \
                             static_cast<uint64_t>(line));         \
  }

// This MACRO is used invoke GENERIC_STR_MATCHER_WITH_LINE MACROS with the
// __LINE__ MACRO.
#define GENERIC_STR_MATCHER(A, OP, B, SRC) \
  GENERIC_STR_MATCHER_WITH_LINE(A, OP, B, __LINE__, SRC)

// This MACRO is used invoke GENERIC_EXPECT_WITH_LINE MACROS with the
// __LINE__ MACRO.
#define GENERIC_EXPECT(A, OP, B, SRC) \
  GENERIC_EXPECT_WITH_LINE(A, OP, B, __LINE__, SRC)

// This MACRO expands with the '==' operator on the LHS and RHS of the
// expression.
#define EXPECT_EQ(A, B) GENERIC_EXPECT(A, ==, B, STRINGIFY(EXPECT_EQ(A, B)))
// This MACRO expands with the '>' operator on the LHS and RHS of the
// expression.
#define EXPECT_GT(A, B) GENERIC_EXPECT(A, >, B, STRINGIFY(EXPECT_GT(A, B)))
// This MACRO expands with the '<' operator on the LHS and RHS of the
// expression.
#define EXPECT_LT(A, B) GENERIC_EXPECT(A, <, B, STRINGIFY(EXPECT_LT(A, B)))
// This MACRO expands with the '==' operator on the LHS and RHS of the
// expression.
#define EXPECT_GTE(A, B) GENERIC_EXPECT(A, >=, B, STRINGIFY(EXPECT_GTE(A, B)))
// This MACRO expands with the '>=' operator on the LHS and RHS of the
// expression.
#define EXPECT_LTE(A, B) GENERIC_EXPECT(A, <=, B, STRINGIFY(EXPECT_LTE(A, B)))
// This MACRO expands with the '<=' operator on the LHS and RHS of the
// expression.
#define EXPECT_NEQ(A, B) GENERIC_EXPECT(A, !=, B, STRINGIFY(EXPECT_NEQ(A, B)))

// This MACRO expands to invoke the compareEquals() method on the LHS and RHS
// strings.
#define STR_EQ(A, B) \
  GENERIC_STR_MATCHER(A, compareEqual(), B, STRINGIFY(STR_EQ(A, B)))
// This MACRO expands to invoke the compareNotEqual() method on the LHS and RHS
// strings.
#define STR_NOT_EQ(A, B) \
  GENERIC_STR_MATCHER(A, compareNotEqual(), B, STRINGIFY(STR_NOT_EQ(A, B)))
// This MACRO expands to invoke the startsWith() method on the LHS and RHS
// strings.
#define STR_STARTS_WITH(A, B) \
  GENERIC_STR_MATCHER(A, startsWith(), B, STRINGIFY(STR_STARTSWITH(A, B)))
// This MACRO expands to invoke the contains() method on the LHS and RHS
// strings.
#define STR_CONTAINS(A, B) \
  GENERIC_STR_MATCHER(A, contains(), B, STRINGIFY(STR_CONTAINS(A, B)))
