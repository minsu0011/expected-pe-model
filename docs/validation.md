# 검증 기준

C1–C5는 연구 후보이며 기준 모델은 v04다. C4의 corrected stress와 실입력 prefix·fallback 문제가 남아 있다. C5의 simulator track은 실제로 관측 가능한 정보만 쓰는 배포 모델이 아니다.

[상세 결과](wiki/Validation-and-Results.md)에서는 결과 수치와 해석 범위를 구분한다. 같은 데이터 버전·표본·split·target·metric·전처리·horizon이 아닌 실험끼리 점수 차이를 개선치로 계산하지 않는다.

[테스트 명령과 범위](testing-notes.md)는 함수·인터페이스 확인용이며 전체 연구의 재학습 성공을 뜻하지 않는다.
