@ECHO OFF
SETLOCAL EnableDelayedExpansion ENABLEEXTENSIONS

set "__BAT_NAME=%~nx0"
set FileFlag=
set PutDump=N
set PutIdentity=N

goto processargs

:usage
    echo USAGE:
    echo   %__BAT_NAME% [flags]
    echo.
    echo.  -h, --help           shows this help
    echo.  -d                   put dump directory
    echo.  -i                   put identity directory
    echo.  -f value             specifies path to usb.json
    goto END

:processargs
    if "%~1"=="" goto validate
    if /i "%~1"=="-f"         set "FileFlag=%~2" & shift & shift & goto processargs
    if /i "%~1"=="-d"         set "PutDump=Y" & shift & goto processargs
    if /i "%~1"=="-i"         set "PutIdentity=Y" & shift & goto processargs
    if /i "%~1"=="-h"         shift & goto usage
    if /i "%~1"=="--help"     shift & goto usage
    SHIFT
    GOTO processargs

:validate
    if not "%FileFlag%"=="" (
      if not exist "%FileFlag%" (
       echo File not exists %FileFlag% & goto END
      )
    )

wmic diskdrive get mediatype | find "Removable Media"|| (
    echo no removable media found & goto END
)

wmic diskdrive where MediaType="Removable Media" get index, caption

set /P choice=Please select device Index from list of removable media:

if ErrorLevel 1 goto END

echo("%choice%"|findstr "^[\"][-][1-9][0-9]*[\"]$ ^[\"][1-9][0-9]*[\"]$ ^[\"]0[\"]$">nul||goto END

wmic diskdrive where MediaType="Removable Media" get index | find "%choice%" > nul|| (
    echo %choice% not in list & goto END
)

echo ======
echo It will delete all data from the device
wmic diskdrive where MediaType="Removable Media" get index, caption | find "%choice%"
echo ======

:PROMPT
SET /P AREYOUSURE=Are you sure (Y/[N])?
IF /I "%AREYOUSURE%" NEQ "Y" goto END

call:format %choice%

for /f %%D in ('wmic volume get DriveLetter^, Label ^| find "QEMU VVFAT"') do set usb=%%D

echo will put files onto %usb%

if "%PutDump%"=="Y" (mkdir %usb%\dump)

if "%PutIdentity%"=="Y" (mkdir %usb%\identity)

if not "%FileFlag%"=="" (COPY %FileFlag% %usb%\usb.json)

EXIT /B %ERRORLEVEL%

:format
@echo off
(
echo select disk %1
echo clean
echo create partition primary size=200
echo format quick fs=fat label="QEMU VVFAT"
) > %TEMP%.script.txt
diskpart /s %TEMP%.script.txt
del %TEMP%.script.txt

:END
endlocal