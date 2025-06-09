clear all;
close all;

% 설정
theta_max = pi;
theta = -theta_max;  % 시작을 -pi로 변경
N = 40000;
d_max = 0.05;   % 랜덤 노이즈 크기 조절

% 선형 시퀀스 생성 (-pi -> pi -> -pi)
half_N = floor(N/2);
linear_inc = linspace(-theta_max, theta_max, half_N);
linear_dec = linspace(theta_max, -theta_max, N - half_N);
theta_linear = [linear_inc, linear_dec];

d_linear = diff([theta_linear(1), theta_linear]);

% 초기값
s = sin(theta);
c = cos(theta);

% 저장용
theta_log = zeros(1, N);
s_log     = zeros(1, N);
err_log   = zeros(1, N);
r_log     = zeros(1, N);
d_values = zeros(1, N);

for k = 1:N
    noise = (rand()*2 - 1)*d_max; % [-d_max, d_max] 노이즈
    d = d_linear(k) + noise;
    theta = theta + d;
    d_values(k) = abs(d);

    % 오일러 방식 회전
    s_new = s + c * d;
    c_new = c - s * d;

    % 근사 정규화
    r2 = s_new^2 + c_new^2;
    inv_r = (3 - r2) / 2;
    s = s_new * inv_r;
    c = c_new * inv_r;

    % 저장
    theta_log(k) = theta;
    s_log(k) = s;
    err_log(k) = (s - sin(theta));
    r_log(k) = sqrt(s^2 + c^2);
end

% 그래프
figure;

subplot(4,1,1);
plot(1:N, theta_log, 'm');
title('theta 값 추이 (-\pi ~ \pi 왕복)');
xlabel('스텝 번호');
ylabel('\theta (rad)');
legend('\theta');

subplot(4,1,2);
plot(1:N, s_log, 'b', 1:N, sin(theta_log), 'r--');
title('sin 근사: 오일러 + 근사 정규화 (파랑), 실제 (빨강 점선)');
xlabel('스텝 번호');
ylabel('sin(\theta)');
legend('오일러 근사', '실제');
ylim([-1.5 1.5]);

subplot(4,1,3);
plot(1:N, err_log, 'b');
title('절대 오차 (sin)');
xlabel('스텝 번호');
ylabel('오차');
legend('오차');

subplot(4,1,4);
plot(1:N, r_log, 'b');
title('근사 정규화된 벡터 크기 (정상: 1)');
xlabel('스텝 번호');
ylabel('벡터 크기');
legend('벡터 크기');
ylim([0.999 1.0025]);
