@echo off
setlocal
python tests\test_m1_reference_validator.py || exit /b 1
python evaluation\run_m1_experiments.py --mode all --dry-run --benign-limit 10 --repeat-limit 5 --additional-repeats 2 --output-dir outputs\m1_smoke_test --resume
endlocal
