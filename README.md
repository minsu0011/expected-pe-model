# Expected P/E

같은 이익에도 시장이 부여하는 배수는 달라진다. 이 프로젝트는 EPS 자체가 아니라 **관측 가능한 시장 상태와 입력 품질에 따라 기대 P/E를 조정하는 방법**을 연구한다. 기준 모델을 유지하면서 후속 후보가 불안정한 상태·희소한 조건·수치 오류에 어떻게 반응하는지 비교했다.

## 전체 구조와 기술

v0.3 upstream의 regime 확률·valuation 입력 → 과거 정보로 계산한 utility → shrinkage·overlay → Expected P/E → 후보별 stress·qualification

- [src/pe_regime_v04](src/pe_regime_v04): 기준 overlay와 실행 인터페이스
- [config](config), [sample_data](sample_data): 설정과 합성 입력
- [portfolio_research](portfolio_research): C1–C5 연구 계열
- [MODEL_REGISTRY.json](MODEL_REGISTRY.json): 기준 모델과 연구 후보의 역할

Python, NumPy, pandas, scikit-learn, LightGBM, PyYAML을 사용하며 C5 시계열 연구에는 PyTorch를 사용한다. upstream의 상태 추정과 v0.4의 배수 조정은 서로 다른 단계다.

## 데이터와 목표

입력은 valuation 관측치와 시점에 맞춘 regime 확률이다. 미래 이익을 맞히는 EPS 모델과 목적이 다르므로 EPS MAE를 이 모델의 성능으로 가져오지 않는다. 합성 시장 생성기는 실패 조건과 수치적 행동을 확인하는 도구이지 실시장 투자 수익의 증거가 아니다.

upstream에는 jump model, HMM, 규칙 기반 상태 등 서로 다른 가정의 출력이 연결될 수 있다. 외부 구현을 자체 모델이라고 부르지 않으며, 이 저장소의 중심은 그 출력을 받아 조정 강도를 결정하는 overlay와 후보 평가다.

## 개발 과정

1. **v0.4를 기준점으로 고정했다.** 새 후보가 좋아 보일 때마다 기준을 바꾸면 어떤 변경이 유효했는지 분리하기 어렵다. registry의 production 항목은 `v04_expected_pe`로 유지했다.
2. **C1은 조정 예산을 문제 삼았다.** rolling dispersion을 이용해 관측 불확실성에 따라 개입 크기를 제한했다. 상태를 안다고 가정하고 크게 움직이는 방식의 대안이다.
3. **C2는 확신이 약한 상태를 줄여 반영했다.** observable-state confidence shrinkage에 sparse-router magnitude taper를 덧붙였다. 희소한 조건에서의 큰 조정이 일반화되는지는 별도 확인이 필요해 secondary 연구로 남겼다.
4. **C3는 단순한 비교군을 남겼다.** 고정 alpha 0.40의 directional consensus는 학습 복잡도를 늘리지 않는 대조군이다. 복잡한 상태 모델의 이득을 판단하려면 이런 기준도 필요하다.
5. **C4는 강건한 잠재 상태를 시도했다.** Huber IRLS 기반 상태 추정과 block 단위 기준 모델 fallback을 묶었다. 하지만 고정된 실행 환경을 맞춘 뒤에도 실입력 prefix·fallback geometry가 계약과 맞지 않는 문제가 남았다.
6. **C5는 순서 정보를 학습하게 했다.** compact GRU를 observable PIT 입력의 Track P와 simulator specialist인 Track S로 나눴다. 시뮬레이터의 정보를 활용한 성과를 실배포 가능한 성과로 옮겨 적지 않았다.
7. **승격 조건을 완화하지 않았다.** C4의 반복 횟수나 fallback 조건을 실험 결과에 맞춰 바꾸지 않았고, C5의 두 track도 합치지 않았다. 후속 후보는 연구용으로 두고 기준 모델을 유지했다.

## 각 후보의 역할

| 계열 | 핵심 질문 | 판단 |
| --- | --- | --- |
| v04 | 기존 overlay가 어떻게 작동하는가 | registry상 production 기준 |
| C1 | 변동성이 클 때 조정 예산을 얼마나 줄일까 | 연구 후보 |
| C2 | 상태 확신과 희소성을 함께 반영할 수 있을까 | 추가 독립 평가 전 secondary |
| C3 | 단순한 고정 합의보다 복잡성이 필요한가 | deterministic control |
| C4 | 강건한 상태 추정이 수치·prefix 계약도 만족하는가 | corrected stress 및 실입력 연결 제약 |
| C5 | 시계열 순서가 유용한가 | P는 prototype, S는 비배포 연구 |

## 결과를 해석하는 방법

기준 모델의 production 표기는 프로젝트 내부 registry의 역할이며 수익성 인증이 아니다. C4의 동결된 연구 후보 지위와 실입력 EPS 연결 단계의 거부 결과도 동시에 성립한다. 한 실험에서 보존된 후보라고 모든 입력에서 실행 가능한 것은 아니다.

후보별 데이터·stress 조건이 달라 직접적인 개선치로 비교하지 않았다. EPS×P/E 연결에는 양의 TTM, 통화, share basis와 horizon 일치가 필요하다. 다음 분기 EPS에 연간 P/E를 바로 곱해 미래 주가 예측으로 해석하지 않는다.

## 실행

Python 3.10 이상에서 저장소 루트를 기준으로:

```powershell
python -m pip install -e .
python -m pe_regime_v04 --help
python -m pytest tests/test_metrics.py -q
```

실제 입력과 합성 입력의 차이는 [데이터 안내](data/README.md), 외부 기여는 [출처](ATTRIBUTION.md)를 따른다.

## 상세 문서

[연구 안내](https://github.com/minsu0011/expected-pe-model/wiki/Home) · [구조](https://github.com/minsu0011/expected-pe-model/wiki/Architecture) · [개발 과정](https://github.com/minsu0011/expected-pe-model/wiki/Development-Journey) · [모델 발전과 승격 판단](https://github.com/minsu0011/expected-pe-model/wiki/Model-Evolution) · [병목과 실험 결정](https://github.com/minsu0011/expected-pe-model/wiki/Experiments-and-Decisions) · [결과와 한계](https://github.com/minsu0011/expected-pe-model/wiki/Validation-and-Results)

문서의 저장소 내부 사본은 [docs/wiki](docs/wiki)에 함께 보관한다.
