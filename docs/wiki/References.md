# 외부 구현과 직접 구성한 부분

jump model·HMM 등 upstream 모델의 구현과 학습 가정은 각각의 저자에게 속한다. 이 저장소의 역할은 시점별 입력을 받아 utility·배수 조정·fallback을 구성하고 후보를 고정 기준으로 비교하는 것이다.

[ATTRIBUTION](../../ATTRIBUTION.md)과 [SOURCE_ATTRIBUTION](../../SOURCE_ATTRIBUTION.md)의 고지를 보존한다. C5의 GRU는 표준 PyTorch 구성 요소를 이용한 연구 모델이며 새로운 GRU 구조를 발명했다는 의미가 아니다.

[기준 소스](../../src/pe_regime_v04) · [후보 계열](../../portfolio_research/research/model_zoo) · [모델 registry](../../MODEL_REGISTRY.json)
