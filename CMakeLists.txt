cmake_minimum_required(VERSION 3.8)
project(enc_sin)

# Default to C++17 for OpenFHE
if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 17)
endif()

# Global settings
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -DPIC -mcmodel=large -pthread")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,--no-as-needed -ldl -pthread")

# Compiler options
if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wall -Wextra -Wpedantic -fpermissive -O3)
endif()

# Find OpenMP
find_package(OpenMP REQUIRED)
find_package(Threads REQUIRED)

# OpenFHE settings
find_package(OpenFHE REQUIRED)

if(OpenFHE_FOUND)
    message(STATUS "Found OpenFHE")
    message(STATUS "OpenFHE Version: ${OpenFHE_VERSION}")
    message(STATUS "OpenFHE Include Dirs: ${OPENFHE_INCLUDE_DIRS}")
    message(STATUS "OpenFHE Libraries: ${OPENFHE_LIBRARIES}")
else()
    message(FATAL_ERROR "OpenFHE not found")
endif()

# Additional include directories for OpenFHE
set(OPENFHE_INCLUDE_DIRS 
    ${OPENFHE_INCLUDE_DIRS}
    /usr/local/include/openfhe
    /usr/local/include/openfhe/core
    /usr/local/include/openfhe/pke
    /usr/local/include/openfhe/binfhe
    /usr/local/include/openfhe/core/lattice
)

include_directories(${OPENFHE_INCLUDE_DIRS})
link_directories(${OPENFHE_LIBDIR})

# Common compile options for OpenFHE executables
set(OPENFHE_COMPILE_OPTIONS
    -fPIC
    -DPIC
    -mcmodel=large
    -pthread
)

set(OPENFHE_LINK_LIBRARIES
    OPENFHEcore
    OPENFHEpke
    OPENFHEbinfhe
    Threads::Threads
    ${CMAKE_DL_LIBS}
)

# BGV test executable
add_executable(bgv_test bgv_test.cpp)
target_include_directories(bgv_test PUBLIC
  ${OPENFHE_INCLUDE_DIRS}
)
target_link_libraries(bgv_test
  ${OPENFHE_LINK_LIBRARIES}
  OpenMP::OpenMP_CXX
)
target_compile_options(bgv_test PRIVATE -fopenmp ${OPENFHE_COMPILE_OPTIONS})

# Sin HE executable
add_executable(sin_he sin_he.cpp)
target_include_directories(sin_he PUBLIC
  ${OPENFHE_INCLUDE_DIRS}
)
target_link_libraries(sin_he
  ${OPENFHE_LINK_LIBRARIES}
  OpenMP::OpenMP_CXX
)
target_compile_options(sin_he PRIVATE -fopenmp ${OPENFHE_COMPILE_OPTIONS}) 