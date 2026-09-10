# 실행 경로

Python 3.10 이상에서 기준 overlay를 설치한다.

```powershell
python -m pip install -e .
python -m pe_regime_v04 --help
python -m pytest tests/test_metrics.py -q
```

[config](../../config)와 [sample_data](../../sample_data)는 입력 schema를 살펴보는 데 사용한다. sample은 합성 데이터이므로 시장 성과를 평가하는 자료가 아니다.

실제 실행은 upstream v0.3의 시점별 확률·valuation 입력을 준비해야 한다. C1–C5는 [별도 연구 script](../../portfolio_research/scripts/model_lab)와 계약을 따르며 기본 overlay CLI가 자동으로 이 후보들을 승격해 쓰지 않는다.

[데이터 안내](../../data/README.md) · [테스트 범위](../testing-notes.md)
