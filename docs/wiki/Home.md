# 연구 안내

EPS 예측은 기업이 벌 이익을 묻고, Expected P/E는 그 이익에 시장이 부여하는 배수를 다룬다. 이 Wiki의 목표는 미래 EPS가 아니라 관측 가능한 상태와 입력 품질에 따른 배수 조정이다.

v0.4 → C1 → C2 → C3 → C4 → C5는 순차적인 성능 우승 기록이 아니다. 기준 overlay를 유지하면서 조정 예산, 상태의 확신, 단순 대조군, 강건 추정, 시계열 표현을 차례로 시험한 계보다. 각 접근의 문제와 남은 조건을 따로 읽도록 문서를 나눴다.

## 읽는 순서

처음 읽는 순서: [구조](Architecture.md) → [개발 과정](Development-Journey.md) → [결과와 한계](Validation-and-Results.md).

실행을 준비한다면 [실행 안내](How-to-Run.md)과 [출처](References.md)를 먼저 확인한다.

## 문서 목록

- [상태 추정과 배수 조정을 나누기](Architecture.md)
- [기준을 유지하면서 후보를 확장한 과정](Development-Journey.md)
- [C1–C5의 변경과 남은 문제](Model-Evolution.md)
- [병목과 승격 판단](Experiments-and-Decisions.md)
- [결과를 어디까지 읽을 것인가](Validation-and-Results.md)
- [실행 경로](How-to-Run.md)
- [외부 구현과 직접 구성한 부분](References.md)

[프로젝트 첫 화면](../../README.md)
