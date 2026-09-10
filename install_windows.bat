@echo off
setlocal
if not exist .venv\Scripts\python.exe (
  python -m venv .venv || exit /b 1
)
.venv\Scripts\python.exe -m pip install --upgrade pip || exit /b 1
.venv\Scripts\python.exe -m pip install -r requirements.txt || exit /b 1
.venv\Scripts\python.exe -m pip install -e . || exit /b 1
.venv\Scripts\python.exe -m pytest -q || exit /b 1
echo Installation and tests completed.
endlocal
