@echo off
start "AI DLP Event Log" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0watch_event_log.ps1"
start "AI DLP Runtime Log" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0watch_runtime_log.ps1"
