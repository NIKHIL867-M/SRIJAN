@echo off
echo Running Threat Analyzer...

cd backend
python run_analyzer.py

echo Opening Frontend...
timeout /t 3

cd ..
start frontend\index.html

pause