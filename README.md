# 동형암호 기반 사인 함수 근사 (Taylor Series, OpenFHE)

이 프로젝트는 OpenFHE의 BGV 스킴을 이용해, 입력값을 정수 스케일링 후 암호화하고 암호공간에서 테일러 다항식(5차)로 sin(x)를 근사하는 실험 코드입니다. 매트랩 코드와 1:1로 동작 구조를 맞췄습니다.

---

## 주요 특징 및 구현 방식

- **입력 생성**: 경계(-π/2 ~ π/2) 내에서 누적 랜덤 워크(백색 노이즈 + 경계 반발력)
- **정수 스케일링**: x_scaled = round(s * x)
- **테일러 계수 정수화**: c1, c3, c5를 s, denom 곱해서 정수화
- **암호화/암호공간 연산**:
    - x_scaled만 암호화
    - 암호공간에서 x³, x⁵, term1/2/3, y_scaled 계산
    - 모든 다항식 연산은 암호공간에서만 수행
- **복호화 및 역스케일링**: y_recovered = y_scaled / (denom * s^5)
- **실제값, 근사값, 오차 출력**

---

## 워크스페이스 최초 사용법 (깃 클론)

```bash
git clone <이 저장소 주소>
cd <저장소 디렉토리>
```

---

## 빌드 및 실행 방법

### 자동 빌드/실행 (추천)

```bash
bash build.sh
```
- 자동으로 build 디렉토리에서 cmake/make 후, 빌드 성공 시 `sin_taylor`를 바로 실행합니다.

### 수동 빌드/실행

```bash
mkdir -p build
cd build
cmake ..
make
./sin_taylor
```

---

## 파라미터 (기본값)
- 샘플링 간격(T): 0.01
- 총 시간(t_end): 0.2 (테스트용, 약 20회 반복)
- 스케일링 상수(s): 100
- 정수화 분모(denom): 120
- 경계: x ∈ [−π/2, π/2]
- 경계 반발력: 0.5
- 랜덤 스텝 표준편차: 0.05
- 평문 모듈러스: 1099512004609 (NTT-friendly, 2^40급 소수)
- 곱셈 뎁스: 5
- 링 차원: 8192

---

## 출력 예시

```
[k, x, 근사값, 실제값, 오차]
  0: x=         0, 근사=           0, 실제=           0, 오차=           0
  1: x=-0.0382573, 근사=  -0.0399893, 실제=   -0.038248, 오차=  0.00174136
  2: x= 0.0404844, 근사=   0.0399893, 실제=   0.0404733, 오차= 0.000483982
  ...

[테일러 근사 전체 소요 시간]
총 274000 ms (33.5 ms/1회)   # 예시: N=8192일 때
```

---

## 제한사항 및 주의사항

- **평문 모듈러스가 충분히 커야 함** (정수화된 다항식 항이 모두 담길 수 있어야 함)
- **입력값이 커질수록(π/2 근처) 테일러 근사 오차가 커질 수 있음**
- **스케일링 상수(s), denom, 파라미터 조정에 따라 근사 오차/암호문 크기/성능이 달라짐**
- OpenFHE 라이브러리 및 의존성 설치 필요
- 대용량 메모리, 멀티스레딩 환경 권장

---

## 참고
- 매트랩(taylor.m) 코드와 완전히 동일한 입력/근사 구조
- 모든 다항식 연산은 암호공간에서만 수행
- 실험 목적: 동형암호 환경에서의 다항식 근사, 오차 및 성능 특성 분석 