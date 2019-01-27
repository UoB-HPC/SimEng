cmake_minimum_required(VERSION 3.5.2)
project(SimEng)

# Require and enable C++17 support, and disable compiler extensions.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable additional compiler warnings for all targets
add_compile_options(-Wall)

add_subdirectory(src)

add_subdirectory(docs)

# googletest
add_subdirectory(lib/googletest)
add_subdirectory(test)
