# 결과를 어디까지 읽을 것인가

[MODEL_REGISTRY.json](../../MODEL_REGISTRY.json)의 production 항목은 v04다. C1–C3는 연구·대조군, C4는 corrected stress 제약이 있는 후보, C5는 두 연구 track이다. 이는 프로젝트 내부의 동결 역할을 설명하며 실시장 수익 보증이 아니다.

모델 입력의 의미, prefix 일관성, numerical fallback, selection freeze를 먼저 보고 성과를 비교해야 한다. dataset/version, sample ID, split, target, metric, 전처리, horizon이 일치하지 않으면 직접적인 개선치로 계산하지 않는다.

EPS×P/E 실험은 양의 native TTM, 통화, share basis, 날짜·기간 호환성을 확인한다. C4가 실제 입력을 거부한 결과는 모델을 바꾸라는 자동 허가가 아니다. static P/E 결과도 미래 multiple을 맞힌 주가 성과와 다르다.

[테스트 범위](../testing-notes.md)는 작은 함수 테스트와 연구 성과의 확인 범위를 분리한다. [한계가 포함된 개발 과정](Development-Journey.md)도 함께 참고한다.
