@echo off
setlocal EnableDelayedExpansion

:: ======================= EDIT THESE =======================
set "GAMEDIR=C:\GOG Games\Star Wars - Battlefront 2\GameData"
set "SERVERNAME=MyLANServer"

:: Map rotation: mission names separated by spaces, e.g.
::   tat2g_con = Mos Eisley, Galactic Civil War, Conquest
::   kas2c_con = Kashyyyk, Clone Wars, Conquest
:: Like BF1, a map may be followed by two reinforcement counts: "tat2g_con 150 150"
set "MAPS=tat2g_con"

:: Players needed before the match starts (game default 2)
set "MINPLAYERS=1"
:: Maximum players (game default 64)
set "MAXPLAYERS=64"

:: AI bots for every game mode (-1 = the mission's own default)
set "BOTS=-1"
:: AI difficulty 1-3 (game default 2)
set "SKILL=2"

:: Network tick rate (game default 20). Game ping = network RTT + up to one tick, so
:: 20 adds ~50 ms; 60 adds ~17 ms. NEVER 0 (the game deliberately crashes on 0).
set "TPS=60"

:: 1 = run without 3D rendering (text status window only, much less CPU/GPU).
:: Needs the proxy dinput8.dll in GameData: unpatched, BF2 silently exits on /norender.
set "NORENDER=1"

:: 1 = on, 0 = off (all on by default in the game)
set "HEROES=1"
set "TEAMDAMAGE=1"
set "SHOWNAMES=1"
:: 1 = players are auto-assigned to a team; 0 = players pick and switch sides (/sideselect)
set "AUTOASSIGN=0"

:: Optional (leave empty for none). Join password is untested in LAN mode.
set "PASSWORD="
:: rcon/admin password, max 15 characters
set "ADMINPW="

:: Advanced, passed through verbatim. Hero tuning switches and their game defaults:
::   /hrunlock 3 /hrunlockvalue 10 /hrplayer 1 /hrteam 3 /hrrespawn 2
:: (meaning of the values not verified). Also /pregametime N.
set "EXTRA="
:: ==========================================================

set "DISPLAY=/resolution 320 240"
if "%NORENDER%"=="1" set "DISPLAY=/norender"

set "OPTS=/playercount %MINPLAYERS% /playerlimit %MAXPLAYERS% /skill %SKILL% /tps %TPS%"
if not "%BOTS%"=="-1" set "OPTS=!OPTS! /bots %BOTS%"
if "%HEROES%"=="0" set "OPTS=!OPTS! /heroes 0"
if "%TEAMDAMAGE%"=="0" set "OPTS=!OPTS! /noteamdamage"
if "%SHOWNAMES%"=="0" set "OPTS=!OPTS! /nonames"
if "%AUTOASSIGN%"=="0" set "OPTS=!OPTS! /sideselect"
if not "%PASSWORD%"=="" set "OPTS=!OPTS! /password %PASSWORD%"
if not "%ADMINPW%"=="" set "OPTS=!OPTS! /adminpw %ADMINPW%"
if not "%EXTRA%"=="" set "OPTS=!OPTS! %EXTRA%"

:: /lan is required: without it the server goes to GOG Galaxy and never opens UDP 3656/3658.
:: /bandwidth /latency /loss /jitter are the network SIMULATOR (fake lag) - do not use them.
:: No /netplayers needed: in LAN mode BF2 already uses a large fixed upload budget.
cd /d "%GAMEDIR%"
if "%NORENDER%"=="1" if not exist "dinput8.dll" echo WARNING: dinput8.dll proxy missing - /norender will make the game exit at once.
echo BattlefrontII.exe /win /autonet dedicated /lan !DISPLAY! /nosound !OPTS! /gamename %SERVERNAME% %MAPS%
BattlefrontII.exe /win /autonet dedicated /lan !DISPLAY! /nosound !OPTS! /gamename %SERVERNAME% %MAPS%
echo Exit code: %errorlevel%
pause
