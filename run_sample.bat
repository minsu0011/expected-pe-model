@echo off
setlocal
if exist .venv\Scripts\python.exe (
  set PYTHON=.venv\Scripts\python.exe
) else (
  set PYTHON=python
)
%PYTHON% -m pe_regime_v04 run --input-csv sample_data\v03_high_sample.csv --truth-csv sample_data\v03_high_sample_truth.csv --config config\v04_bottleneck.yaml --output-dir outputs\sample
endlocal
