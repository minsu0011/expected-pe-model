# 기준을 유지하면서 후보를 확장한 과정

## v0.4: 배수 조정의 기준점

초기 v0.4는 upstream 확률과 valuation 입력을 받아 기대 배수를 조정하는 실행 기준이었다. 다음 질문은 “더 복잡한 후보를 만들 수 있는가”보다 “어떤 입력 상태에서 조정하면 위험한가”였다. 후보를 비교하는 동안 registry의 production 기준으로 유지했다. 이 역할은 실시장 수익을 인증한다는 뜻이 아니다.

## C1: 조정 예산을 먼저 제한

입력이 불안정한데도 배수를 크게 바꾸면 상태 추정 오차가 그대로 조정값에 전달된다. C1은 과거 rolling dispersion 기반 budget으로 개입 크기를 제한했다. 복잡한 상태 모델 이전에 조정의 크기를 통제하려는 접근이다. 구현은 연구 후보로 남았고 production 승격 근거로 삼지 않았다. 예산 제한 자체가 새 데이터에서 유효한지는 독립적인 평가가 필요하다.

## C2: 상태의 확신과 희소성을 반영

C2는 관측 가능한 상태의 확신에 따라 shrinkage를 적용했다. 희소한 조건에서 큰 개입이 반복되는 문제에는 magnitude taper를 덧붙였다. 전체 불확실성에 하나의 예산을 두는 C1과 달리, 어떤 상태를 얼마나 믿을지 묻는 접근이다. 후속 overlay는 추가 독립 평가 전 secondary로 남겼다. 희소 상태의 반응이 일반화됐다고 판단할 근거가 부족하기 때문이다.

## C3: 단순한 합의를 대조군으로 유지

C3는 alpha 0.40의 고정 directional consensus다. 복잡한 후보가 이런 결정적 대조군보다 나은지 볼 수 있도록 유지했다. 별도 학습으로 상태 변화에 적응하는 구조는 아니며, registry에서도 deterministic control이다. 최신 학습 모델로 대체하기보다 복잡성의 가치를 비교하는 기준으로 남겼다.

## C4: 강건 추정과 실패 시 복귀

C4는 observable fair-value state를 강건하게 추정하려 했다. Huber IRLS, 시간순 block fit, 수치 실패 시 v0.4 fallback을 묶었다. 후속 EPS 연결에서는 추가 BLAS library 문제를 분리한 뒤에도 실입력의 prefix와 fallback geometry가 고정 계약에 맞지 않았다. 실행 의존성 하나를 해결했다고 모델 적용 조건도 충족했다고 보지 않았다. corrected stress가 미완료인 연구 후보로 남겼고, 실입력 연결의 실패를 없애려고 고정 수치 규칙을 완화하지 않았다.

## C5: 시계열 정보가 추가하는 가치

C5는 compact GRU를 사용해 시간 순서가 도움이 되는지 살폈다. observable PIT prototype인 Track P와 simulator specialist인 Track S를 분리했다. 두 track은 이용할 수 있는 정보가 다르므로 점수를 합쳐 한 모델의 성과로 해석하지 않는다. P는 prototype, S는 실배포 대상이 아닌 연구로 남았다. 시뮬레이터 안의 적응이 관측 입력만으로도 유지되는지가 핵심 경계다.

개발 과정의 결론은 [registry](../../MODEL_REGISTRY.json)의 production 기준 유지다. 동결된 연구 후보, secondary 후보, 실입력에서 거부된 연결 결과는 서로 다른 상태이며 하나의 승패 순위로 합치지 않았다.
