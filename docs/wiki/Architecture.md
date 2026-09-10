# 상태 추정과 배수 조정을 나누기

v0.4는 upstream regime 생성기가 아니라 그 출력 위의 overlay다. 상태 확률이 관측 시점에 준비돼 있어야 utility·조정 강도를 계산할 수 있다. upstream이 바뀌면 overlay 출력이 달라져도 overlay 자체의 개선이라고 단정할 수 없다.

[src](../../src/pe_regime_v04)에는 실행 CLI, feature·metric·valuation 처리가 있고 [portfolio_research](../../portfolio_research)에는 별도 후보가 있다. 기본 실행과 연구 후보를 같은 자동 선택 경로에 넣지 않았다.

배수 조정은 미래 이익량과 다른 축이다. EPS 연결에서는 날짜·통화·주식 수 기준·양의 TTM을 확인해야 한다. static P/E 시나리오를 horizon이 다른 EPS에 적용하면 실제 미래 주가를 검증한 것이 아니다.

합성 입력은 실패 상황을 통제하는 데 유용하다. 하지만 simulator state를 직접 아는 모델과 observable-input 모델의 정보량은 다르다. C5의 Track P/S 분리는 이 차이를 드러낸다.
