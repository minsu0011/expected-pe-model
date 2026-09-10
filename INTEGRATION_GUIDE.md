# v0.3 통합 가이드

현재 v0.4 계약은 append 104 / canonical 254 / bundled 168이다. MG1 직전 96개 append 열은 exact positional prefix이고 마지막 8개 matured-proxy audit 열은 default-off tail이다. MG1은 HARNESS 2.6 fresh tuning에서 기각됐으므로 `v04_expected_pe`, gap/state, 기본값과 version은 바뀌지 않았다.

## 안전한 1단계: overlay로 검증

v0.3 CLI가 생성한 canonical CSV를 그대로 입력한다.

```powershell
python -m pe_regime_v04 run `
  --input-csv <V03_OUTPUT.csv> `
  --config config\v04_bottleneck.yaml `
  --output-dir outputs\v04_overlay
```

이 단계에서는 v0.3 source를 수정하지 않는다.

## 2단계: 실제 v0.3 저장소에 실험 폴더 설치

```powershell
python scripts\install_overlay_into_v03.py `
  --target C:\path\to\PE_Regime_Engine_v0.3.0
```

이 스크립트는 v0.3 core를 패치하지 않고 다음 위치로 overlay를 복사한다.

```text
<V03>/experiments/pe_regime_v04_overlay/
```

## 3단계: in-pipeline 통합

다음 인터페이스로 upstream pipeline과 연결한다.

```python
v03_frame = run_v03_pipeline(...)
v04_frame, v04_diagnostics = apply_v04_layers(v03_frame, config)
```

통합 시 현재 CSV I/O wrapper의 계산 순서를 그대로 보존하되 다음은 바꿔야 한다.

1. no-regime와 with-regime Expected P/E를 v0.3 high의 동일 outer fold scheduler로 실행.
2. 두 후보에 같은 fold boundaries, seed, LightGBM hyperparameters, imputer, sample weights 사용.
3. v0.3 `ml_expected_pe`를 raw ML incumbent로 유지하고, 최종 production reference는 기존 guarded `v04_expected_pe`로 유지.
4. `matched_best`가 shifted OOS에서 이길 때만 incumbent gate에 진입.
5. statistical candidate가 guarded ML을 이길 때만 최종값에 개입.
6. 기존 canonical 150열은 수정하지 않고 v0.4 namespace 열을 append.
7. `v04_matured_proxy_regularized_expected_pe`와 7개 audit 열은 valuation 뒤 default-off tail로만 유지하고 main/gap/state에 연결하지 않음.

새 promotion 실험은 같은 common fair-truth mask에서 primary `v04_expected_pe`와 anti-gaming `ml_expected_pe`가 모두 HARNESS 2.6 기준을 통과해야 한다. MG1 heldout 6803/6907/7001/7103/7207은 reserved/spent지만 unopened이므로 열거나 재사용하지 않는다.

## 금지

- v0.3 PIT EPS ledger, SEC parser, split basis, Observed P/E 수정
- current-state regime와 forward-return forecast probability를 같은 의미로 노출
- current row error로 current row model weight 계산
- random split
- synthetic truth를 production feature/label로 사용
- 한 seed 결과만으로 high config 교체
- 실패한 MG1 routing family의 threshold/horizon/window/weight 재튜닝 또는 seed 예외
- candidate lock 없이 heldout/downstream review 실행
