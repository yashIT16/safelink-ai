Set WshShell = CreateObject("WScript.Shell")
' Run Python ML API invisibly on port 5001
WshShell.Run "cmd /c cd /d ""D:\scaning tool\safelink-ai\ml-model-python"" && python app.py > flask_api_autostart.log 2>&1", 0, False

' Run Node API invisibly on port 3001
WshShell.Run "cmd /c cd /d ""D:\scaning tool\safelink-ai\backend-node"" && npm start > node_server_autostart.log 2>&1", 0, False
