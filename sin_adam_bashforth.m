% 설정
theta = 0;
N = 40000;
d_max = 0.05;  % 최대 랜덤 노이즈 크기
theta_max = pi; % 최대 각도 (파이)

% 큰 흐름: 0 -> pi -> 0, 선형 증가/감소를 위한 선형 시퀀스 생성
half_N = floor(N/2);
linear_inc = linspace(0, theta_max, half_N);       % 0 to pi
linear_dec = linspace(theta_max, 0, N - half_N);   % pi to 0
theta_linear = [linear_inc, linear_dec];

% 각 스텝에서의 선형 변화량 d_linear 계산
d_linear = diff([0, theta_linear]); % theta 변화량, 첫값은 0 포함

% 초기값 (Adams-Bashforth는 두 스텝 필요)
s_ab = sin(theta); c_ab = cos(theta);
s_prev = s_ab; c_prev = c_ab;

% 한 스텝 먼저 진행해서 prev2 값 확보 (초기 랜덤 노이즈 포함)
d = d_linear(1) + (rand()*2 - 1)*d_max; % 선형 변화량에 노이즈 추가
theta = theta + d;
s_now = s_prev + c_prev * d;
c_now = c_prev - s_prev * d;

% 근사 정규화 (1/루트 근사)
r2 = s_now^2 + c_now^2;
inv_r = (3 - r2) / 2;
s_now = s_now * inv_r;
c_now = c_now * inv_r;

% prev2 설정
s_prev2 = s_prev; c_prev2 = c_prev;
s_prev = s_now; c_prev = c_now;

% 저장용
theta_log = zeros(1, N);
s_ab_log  = zeros(1, N);
err_ab    = zeros(1, N);
r_log     = zeros(1, N);
sin_taylor = zeros(1, N);
err_taylor = zeros(1, N);
d_values = zeros(1, N); % 변화량 저장

for k = 1:N
    % 선형 변화량에 랜덤 노이즈 더하기
    noise = (rand()*2 - 1)*d_max;
    d = d_linear(k) + noise;
    theta = theta + d;
    d_values(k) = abs(d);  % 절대값 저장

    % Adams-Bashforth 2차 근사
    s_new = s_prev + (3/2)*c_prev*d - (1/2)*c_prev2*d;
    c_new = c_prev - (3/2)*s_prev*d + (1/2)*s_prev2*d;

    % 근사 정규화
    r2 = s_new^2 + c_new^2;
    inv_r = (3 - r2) / 2;
    s_new = s_new * inv_r;
    c_new = c_new * inv_r;

    % 이전 값 업데이트
    s_prev2 = s_prev;
    c_prev2 = c_prev;
    s_prev  = s_new;
    c_prev  = c_new;

    s_ab = s_new;
    c_ab = c_new;

    % 저장
    theta_log(k) = theta;
    s_ab_log(k) = s_ab;
    r_log(k) = sqrt(r2);
    err_ab(k) = abs(s_ab - sin(theta));

    % 테일러 급수 5차 근사 및 오차 계산 (theta를 -pi~pi 범위로 제한)
    t = mod(theta + pi, 2*pi) - pi;  % -pi ~ pi
    sin_taylor(k) = t - (t^3)/6 + (t^5)/120;
    err_taylor(k) = abs(sin_taylor(k) - sin(theta));
end

% 그래프
figure;

subplot(3,1,1);
plot(1:N, s_ab_log, 'b', 1:N, sin(theta_log), 'r--', 1:N, sin_taylor, 'g:');
title('sin 근사: AB2 (파랑), 실제 (빨강 점선), 테일러 5차 (초록 점선)');
xlabel('스텝 번호');
ylabel('sin(theta)');
legend('AB2 근사', '실제', '테일러 5차 근사');
ylim([-1.5 1.5]);

subplot(3,1,2);
plot(1:N, err_ab, 'b');  % 클리핑 없이 절대 오차만 플롯
title('절대 오차 (sin) - AB2 오차');
xlabel('스텝 번호');
ylabel('오차');
legend('AB2 오차');

subplot(3,1,3);
plot(1:N, r_log, 'b');
title('근사 정규화된 벡터 크기 (정상: 1)');
xlabel('스텝 번호');
ylabel('값');
legend('근사된 벡터 크기');
ylim([0.9 1.1]); 