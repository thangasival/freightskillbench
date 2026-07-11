@echo off
REM Generate FreightSkillBench manuscript tables and figures.
REM Usage:
REM   run_generate_tables_figures.cmd outputs\FINAL_PHASE6_LIVE_RESULTS manuscript_artifacts

set INPUT_DIR=%1
set OUTPUT_DIR=%2

if "%INPUT_DIR%"=="" set INPUT_DIR=outputs\FINAL_PHASE6_LIVE_RESULTS
if "%OUTPUT_DIR%"=="" set OUTPUT_DIR=manuscript_artifacts

python scripts\generate_paper_tables_figures.py --input-dir "%INPUT_DIR%" --output-dir "%OUTPUT_DIR%"
