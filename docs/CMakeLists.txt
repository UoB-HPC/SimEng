find_program(SPHINX_EXECUTABLE NAMES sphinx-build
             DOC "Sphinx documentation generator")
if (SPHINX_EXECUTABLE)
  message(STATUS "Sphinx found: ${SPHINX_EXECUTABLE}")
  add_custom_target(docs VERBATIM
                    COMMAND ${SPHINX_EXECUTABLE}
                    -c ${CMAKE_CURRENT_SOURCE_DIR}/sphinx
                    ${CMAKE_CURRENT_SOURCE_DIR}/sphinx
                    ${CMAKE_CURRENT_BINARY_DIR}/sphinx)
else()
  message(STATUS "Sphinx NOT found (set SPHINX_EXECUTABLE if needed)")
endif()
