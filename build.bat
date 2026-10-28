@echo off
setlocal
:: Builds src\dinput8.dll (x86) with Visual Studio 2022 Build Tools.
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat"
if exist "%VCVARS%" goto build
echo vcvars32.bat not found: "%VCVARS%"
echo Install "Visual Studio 2022 Build Tools" with the C++ workload, or edit VCVARS.
exit /b 1

:build
call "%VCVARS%" >nul || exit /b 1
cd /d "%~dp0src"
cl /nologo /O2 /MT /EHsc /LD dinput8_proxy.cpp /Fo:"%~dp0src\\" /Fe:dinput8.dll /link /DEF:dinput8_proxy.def ws2_32.lib kernel32.lib || exit /b 1
echo Built "%~dp0src\dinput8.dll"
