cmake_minimum_required(VERSION 3.5.1)

project(sin_he CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

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
    message(STATUS "OpenFHE Include Dirs: ${OpenFHE_INCLUDE_DIRS}")
    message(STATUS "OpenFHE Libraries: ${OpenFHE_LIBRARIES}")
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

# Polynomial multiplication test executable
add_executable(polynomial_mult_test polynomial_mult_test.cpp)
target_include_directories(polynomial_mult_test PUBLIC
  ${OPENFHE_INCLUDE_DIRS}
)
target_link_libraries(polynomial_mult_test
  ${OPENFHE_LINK_LIBRARIES}
  OpenMP::OpenMP_CXX
)
target_compile_options(polynomial_mult_test PRIVATE -fopenmp ${OPENFHE_COMPILE_OPTIONS})

# Sin Taylor Plain executable
add_executable(sin_taylor_plain sin_taylor_plain.cpp)
target_include_directories(sin_taylor_plain PUBLIC
  ${OPENFHE_INCLUDE_DIRS}
)
target_link_libraries(sin_taylor_plain
  ${OPENFHE_LINK_LIBRARIES}
  OpenMP::OpenMP_CXX
)
target_compile_options(sin_taylor_plain PRIVATE -fopenmp ${OPENFHE_COMPILE_OPTIONS})

# Sin Taylor Third executable
add_executable(sin_taylor_third sin_taylor_third.cpp)
target_include_directories(sin_taylor_third PUBLIC
  ${OPENFHE_INCLUDE_DIRS}
)
target_link_libraries(sin_taylor_third
  ${OPENFHE_LINK_LIBRARIES}
  OpenMP::OpenMP_CXX
)
target_compile_options(sin_taylor_third PRIVATE -fopenmp ${OPENFHE_COMPILE_OPTIONS})

# Sin Taylor Fifth executable
add_executable(sin_taylor_fifth sin_taylor_fifth.cpp)
target_include_directories(sin_taylor_fifth PUBLIC
  ${OPENFHE_INCLUDE_DIRS}
)
target_link_libraries(sin_taylor_fifth
  ${OPENFHE_LINK_LIBRARIES}
  OpenMP::OpenMP_CXX
)
target_compile_options(sin_taylor_fifth PRIVATE -fopenmp ${OPENFHE_COMPILE_OPTIONS})

if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
else()
    set( CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS})
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} )
endif() 