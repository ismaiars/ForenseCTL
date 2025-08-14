
@echo off
echo ========================================
echo ForenseCTL Standalone - Instalacion
echo ========================================
echo.
echo Copiando ForenseCTL.exe a C:\ForenseCTLif not exist "C:\ForenseCTL" mkdir "C:\ForenseCTL"
copy "ForenseCTL.exe" "C:\ForenseCTL\ForenseCTL.exe"
echo.
echo Agregando al PATH del sistema...
setx PATH "%PATH%;C:\ForenseCTL" /M
echo.
echo ========================================
echo Instalacion completada!
echo Ejecuta 'ForenseCTL' desde cualquier ubicacion
echo ========================================
pause
