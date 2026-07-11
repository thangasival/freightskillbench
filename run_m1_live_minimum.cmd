@echo off
setlocal
REM Configure provider environment variables before running this file.
python evaluation\run_m1_experiments.py --mode all --live --benign-limit 60 --repeat-limit 15 --additional-repeats 2 --delay-between-repeats 60 --output-dir outputs\m1_experiments --resume
endlocal
