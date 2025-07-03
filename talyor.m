clear; clc;

% 파라미터
T = 0.01;       % 샘플링 간격
t_end = 60;     % 총 시간
t = 0:T:t_end;
N = length(t);

s = 100;        % 스케일링 상수
denom = 120;    % 정수화 분모

% 누적각 초기값
x = zeros(1, N);
x(1) = 0;

% 경계 설정 (rad)
x_min = -pi/2;
x_max = pi/2;

% 경계 반발력 세기
k_repulse = 0.5;

for k = 2:N
    % 랜덤 스텝 (백색노이즈)
    step = 0.05 * randn();

    % 경계 반발력: 범위를 벗어나면 반대방향 힘 작용
    if x(k-1) > x_max
        step = step - k_repulse * (x(k-1) - x_max);
    elseif x(k-1) < x_min
        step = step + k_repulse * (x_min - x(k-1));
    end

    % 다음 위치
    x(k) = x(k-1) + step;
end

% 정수화
x_scaled = round(s * x);

% 테일러 다항식 계수 (sin)
c1 = 1;      
c3 = -1/6;   
c5 = 1/120;  

% 정수화 계수
ic1 = c1 * denom * s^4;    
ic3 = c3 * denom * s^2;    
ic5 = c5 * denom;          

% 정수 연산
term1 = round(ic1) * x_scaled;
term2 = round(ic3) * (x_scaled.^3);
term3 = round(ic5) * (x_scaled.^5);

y_scaled = term1 + term2 + term3;

% 역스케일링
y_recovered = y_scaled / (denom * s^5);

% 실제 sin값
y_true = sin(x);

% 그래프 출력
figure;

subplot(3,1,1);
plot(t, x, 'b', 'LineWidth', 1.5);
xlabel('Time [s]');
ylabel('Input angle (rad)');
title('Bounded random walk input angle');
grid on;

subplot(3,1,2);
plot(t, y_true, 'k--', 'LineWidth', 1.5); hold on;
plot(t, y_recovered, 'r', 'LineWidth', 1.5);
legend('True sin(x)', 'Taylor approx');
ylabel('sin(x)');
title('Sin function approximation');
grid on;

subplot(3,1,3);
plot(t, abs(y_true - y_recovered), 'm', 'LineWidth', 1.2);
xlabel('Time [s]');
ylabel('Absolute error');
title('Approximation error');
grid on;
