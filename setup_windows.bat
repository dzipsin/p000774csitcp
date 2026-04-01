@echo off
python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip -q
python -m pip install -r requirements.txt
echo Done. Run: .venv\Scripts\activate ^&^& python src\app.py
