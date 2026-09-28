@echo off
cd /d "%~dp0"
title CMS - close this window to stop the site
if not exist db\cms.db python db\init_db.py
echo.
echo  Admin panel:  http://localhost:5000/admin
echo  Website:      http://localhost:5000
echo.
echo  Close this window to stop the site.
echo.
start "" http://localhost:5000/admin
python app.py
pause
