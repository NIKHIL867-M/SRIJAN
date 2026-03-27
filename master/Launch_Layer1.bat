@echo off
echo Launching SentinelAI Layer 1 Dashboard...

:: This command launches Windows Terminal, maximizes it, and slices it into a 3x2 grid.
wt -M -d . cmd /k "title AMSI Monitor ^& echo [SentinelAI] Starting AMSI... ^& titan_amsi.exe" ; ^
split-pane -V -d . cmd /k "title Network Monitor ^& echo [SentinelAI] Starting Network... ^& titan.exe" ; ^
split-pane -V -d . cmd /k "title Process Monitor ^& echo [SentinelAI] Starting Process... ^& titan_process.exe" ; ^
move-focus left ; move-focus left ; ^
split-pane -H -d . cmd /k "title File Monitor ^& echo [SentinelAI] Starting File... ^& file_test.exe" ; ^
move-focus right ; ^
split-pane -H -d . cmd /k "title App Monitor ^& echo [SentinelAI] Starting App... ^& applog_test.exe" ; ^
move-focus right ; ^
split-pane -H -d . cmd /k "title USB Monitor ^& echo [SentinelAI] Starting USB... ^& usb_test.exe"

exit