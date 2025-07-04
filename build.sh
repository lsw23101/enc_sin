#!/bin/bash

# build 디렉토리로 이동
cd build

# CMake 빌드 실행
cmake .. && make

# 빌드 성공했을 때만 실행
if [ $? -eq 0 ]; then
    echo -e "\n실행 결과:\n"
    ./slotwise_poly_mult_test
else
    echo "빌드 실패!"
fi 