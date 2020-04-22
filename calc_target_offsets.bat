@echo off

echo Calculating offsets, please wait...
echo.

pushd tools

set cmd=dumpbin.exe /IMPORTS:ntoskrnl.exe "%windir%\system32\drivers\srvnet.sys" ^| findstr /c:"Import Address Table"
for /f "tokens=1" %%i in ('"%cmd%"') do set iat=%%i

set cmd=dumpbin.exe /IMPORTS:ntoskrnl.exe "%windir%\system32\drivers\srvnet.sys" ^| findstr /e /n IoSizeofWorkItem
for /f "tokens=1 delims=:" %%i in ('"%cmd%"') do set /a IoSizeofWorkItem=%%i-17

set cmd=dumpbin.exe /IMPORTS:ntoskrnl.exe "%windir%\system32\drivers\srvnet.sys" ^| findstr /e /n RtlCopyUnicodeString
for /f "tokens=1 delims=:" %%i in ('"%cmd%"') do set /a RtlCopyUnicodeString=%%i-17

set w=.echo ==========
set w=%w%; .printf \"\OFFSETS = { \x23\n\"
set w=%w%; .catch { .printf \"\    'srvnet!SrvNetWskConnDispatch': 0x%%X, \x23\n\", srvnet!SrvNetWskConnDispatch-srvnet }
set w=%w%; .catch { .printf \"\    'srvnet!imp_IoSizeofWorkItem': 0x%%X, \x23\n\", %iat%-srvnet+0n%IoSizeofWorkItem%*8 }
set w=%w%; .catch { .printf \"\    'srvnet!imp_RtlCopyUnicodeString': 0x%%X, \x23\n\", %iat%-srvnet+0n%RtlCopyUnicodeString%*8 }
set w=%w%; .echo ==========
set w=%w%; q

set cmd=cdb.exe -y "SRV*%cd%*https://msdl.microsoft.com/download/symbols"
set cmd=%cmd% -z "%windir%\system32\drivers\srvnet.sys"
set cmd=%cmd% -c "%w%"

%cmd% | findstr #

set w=.echo ==========
set w=%w%; .catch { .printf \"    'nt!IoSizeofWorkItem': 0x%%X, \x23\n\", ntoskrnl!IoSizeofWorkItem-ntoskrnl }
set w=%w%; .catch { .printf \"    'nt!MiGetPteAddress': 0x%%X \x23\n\", ntoskrnl!MiGetPteAddress-ntoskrnl }
set w=%w%; .printf \"} \x23\n\"
set w=%w%; .echo ==========
set w=%w%; q

set cmd=cdb.exe -y "SRV*%cd%*https://msdl.microsoft.com/download/symbols"
set cmd=%cmd% -z "%windir%\system32\ntoskrnl.exe"
set cmd=%cmd% -c "%w%"

%cmd% | findstr #

popd
pause
