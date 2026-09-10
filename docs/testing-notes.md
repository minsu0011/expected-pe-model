# 테스트와 실행 범위

저장소 루트에서 의존성을 준비한 뒤 다음 범위를 확인할 수 있다.

```powershell
python -m pytest tests/test_metrics.py tests/test_features.py tests/test_config.py tests/test_valuation.py -q
```

외부 원천 전체 수집이나 금융 성과 재현을 의미하지 않는다.

C1–C5는 연구 후보이며 기준 모델은 v04다. C4의 corrected stress와 실입력 prefix·fallback 문제가 남아 있다. C5의 simulator track은 실제로 관측 가능한 정보만 쓰는 배포 모델이 아니다.

테스트 실행과 전체 원천 수집·학습은 별개다. 연구 결과는 [README](../README.md)의 당시 기록과 입력 조건을 함께 읽는다.
