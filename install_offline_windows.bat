@echo off
setlocal
if not exist wheelhouse (
  echo wheelhouse directory is missing.
  exit /b 2
)
if not exist .venv\Scripts\python.exe (
  python -m venv .venv || exit /b 1
)
set PIP_NO_INDEX=1
set PIP_FIND_LINKS=%CD%\wheelhouse
.venv\Scripts\python.exe -m pip install --no-index --find-links wheelhouse -r requirements.txt || exit /b 1
.venv\Scripts\python.exe -m pip install --no-index --find-links wheelhouse pe-regime-v04-overlay==0.4.0 || exit /b 1
.venv\Scripts\python.exe -m pytest -q || exit /b 1
echo Offline installation and tests completed.
endlocal
