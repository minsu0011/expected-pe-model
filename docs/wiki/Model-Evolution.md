# C1–C5의 변경과 남은 문제

| 계열 | 변경 이유 | 변경한 것 | 남은 판단 |
| --- | --- | --- | --- |
| C1 | 불안정한 입력에서 과도한 배수 조정 | causal rolling dispersion budget | 별도 연구 자격 평가 필요 |
| C2 | 상태 확신·희소성에 따른 위험 | confidence shrinkage, magnitude taper | 새 독립 formal 평가 전 secondary |
| C3 | 복잡성 자체의 가치를 비교 | 고정 alpha 0.40 합의 | deterministic control 유지 |
| C4 | 이상치·상태 변화에 강건한 추정 | IRLS 80회 상한, block-v04 fallback, log shrink 0.50 | corrected stress와 실입력 geometry 미해결 |
| C5 P | 관측 가능한 sequence 정보 | compact GRU, PIT 입력 | prototype |
| C5 S | simulator 조건에서 specialist 작동 확인 | simulator-aware sequence | 배포 가능한 정보 집합이 아님 |

C4의 80회 상한과 fallback을 결과에 맞춰 바꾸면 같은 후보가 아니다. 수치 실패를 모두 무시하는 방식도 아니다. 허용한 실패에서만 block fallback을 적용해야 한다.

[후보 구현](../../portfolio_research/research/model_zoo)과 [후보별 테스트](../../portfolio_research/tests/model_lab)를 함께 읽으면 된다. EPS 연구의 model zoo와 이 후보들의 목적 함수는 다르다.
