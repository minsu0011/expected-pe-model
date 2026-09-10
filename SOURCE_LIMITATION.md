# upstream 연결 범위

v0.4를 시작할 때 사용한 v0.3 자료는 high 설정의 출력 CSV·JSON, 정답, 설정과 release metadata였다. 전체 v0.3 코드와 테스트는 이 자료에 포함되지 않았다.

그래서 기존 출력 계약 위에 독립적인 overlay를 구성했다. 과거 v0.2나 보고서에서 추정한 코드를 v0.3 구현으로 대체하지 않았다.

실제 upstream 생성기는 별도 필요하다. [통합 가이드](INTEGRATION_GUIDE.md)에 따라 v0.3의 canonical 입력과 기존 PIT·주식 수·Observed P/E 계산을 유지한 채 연결한다.
