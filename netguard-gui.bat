@echo off
rem Opens the NetGuard GUI as a small app window (Edge). NetGuard must already be running (as Administrator).
start "" msedge --app=http://127.0.0.1:8080 2>nul || start "" http://127.0.0.1:8080
