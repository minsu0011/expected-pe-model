# 기준을 유지하면서 후보를 확장한 과정

초기 v0.4는 upstream 확률과 valuation 입력을 받아 기대 배수를 조정하는 실행 기준이었다. 다음 질문은 “더 복잡한 후보를 만들 수 있는가”보다 “어떤 입력 상태에서 조정하면 위험한가”였다.

C1은 rolling dispersion 기반 budget으로 개입 크기를 제한했다. C2는 관측 가능한 상태의 확신에 따라 shrinkage를 적용했고, 희소 상태에서 큰 개입이 반복되는 문제에 magnitude taper를 덧붙였다.

C3는 alpha 0.40의 고정 directional consensus다. 복잡한 후보가 이런 결정적 대조군보다 나은지 볼 수 있도록 유지했다. 모든 계열을 학습형 모델이라고 표현하지 않는 이유다.

C4는 observable fair-value state를 강건하게 추정하려 했다. Huber IRLS, 시간순 block fit, 수치 실패 시 v0.4 fallback을 묶었다. 후속 EPS 연결에서는 추가 BLAS library 문제를 분리한 뒤에도 실입력의 prefix와 fallback geometry가 고정 계약에 맞지 않았다. 환경 문제 하나를 해결했다고 모델 적용 조건도 충족했다고 보지 않았다.

C5는 compact GRU를 사용해 시간 순서가 도움이 되는지 살폈다. observable PIT prototype과 simulator specialist를 분리했고 둘 다 production으로 자동 승격하지 않았다.

개발 과정의 결론은 [registry](../../MODEL_REGISTRY.json)의 production 기준 유지다. 동결된 연구 후보, secondary 후보, 실입력에서 거부된 연결 결과는 서로 다른 상태이며 하나의 승패 순위로 합치지 않았다.
