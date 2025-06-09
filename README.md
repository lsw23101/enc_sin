# Homomorphic Encryption Sin Approximation

동형암호를 사용하여 sin 함수를 근사하는 프로젝트입니다.

## 필수 요구사항

- C++ 17 이상
- OpenFHE 라이브러리
- CMake 3.8 이상
- OpenMP
- 멀티스레딩 지원

## 빌드 방법

```bash
mkdir build
cd build
cmake ..
make
```

## 실행 방법

빌드 디렉토리에서:
```bash
./sin_he
```

## 프로젝트 구조

- `sin_he.cpp`: 1차 근사 구현 코드
- `CMakeLists.txt`: CMake 빌드 설정 파일

## 현재 구현 상태

### 1차 근사 구현 (sin_he.cpp)
- OpenFHE 라이브러리의 BGV 스킴 사용
- 1차 근사 방식 구현: sin(θ + d) ≈ sin(θ) + cos(θ)d
- 스케일링 상수: 10^3
- 파라미터 설정:
  - 평문 모듈러스: 65537 (2^16 + 1, Fermat 소수)
  - 곱셈 깊이: 8
  - 링 차원: 8192 (2^13)

### 현재 문제점
- 스케일링 조정 과정에서 정확도 문제 발생
- 암호화된 연산 결과가 실제 값과 큰 차이를 보임

### 다음 단계
- 스케일링 방식 개선
- 정확도 향상을 위한 파라미터 조정

## 참고 자료
- first_order.m: 매트랩으로 구현한 1차 근사 코드
- sin_approximation.m: Adams-Bashforth 2차 근사 코드

## 주의사항

- OpenFHE 라이브러리가 시스템에 올바르게 설치되어 있어야 합니다.
- 대용량 메모리를 사용할 수 있어야 합니다.
- 멀티스레딩을 지원하는 환경이 필요합니다. 