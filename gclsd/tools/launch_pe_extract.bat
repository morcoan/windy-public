@echo off
set PYTHONPATH=current repository root\gclsd\src
cd /d current repository root
"current repository root\gclsd\.venv\Scripts\python.exe" -m windy_gclsd.data.assemblage_pairs ^
  --db "D:\assemblage\pe\extracted\winpe.sqlite" ^
  --binary-dir "D:\assemblage\pe\extracted\binaries" ^
  --windy-exe "current repository root\target\debug\windy.exe" ^
  --output "D:\assemblage\pe_full_pairs.jsonl" ^
  --workers 8 ^
  1>"D:\assemblage\pe_extract.log" 2>"D:\assemblage\pe_extract.err"
