import os
import shutil
import uvicorn
from pathlib import Path
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse

SOC_DIR = Path("/home/prizux/prizux/backend/SoC")
AUTH_LOG_PATH = SOC_DIR / "auth.log"

app = FastAPI()

@app.get("/admin/dashboard")
async def admin_dashboard():
    admin_html = """
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8"><title>Prizux Central Control</title>
        <style>
            body { background: #0f172a; color: #f1f5f9; font-family: sans-serif; margin: 0; display: flex; }
            .sidebar { width: 260px; background: #1e293b; height: 100vh; padding: 20px; box-sizing: border-box; }
            .main { flex: 1; padding: 40px; overflow-y: auto; }
            .card { background: #334155; border-radius: 12px; padding: 25px; margin-bottom: 30px; border: 1px solid #475569; }
            .log-view { background: #000; color: #22c55e; padding: 20px; border-radius: 8px; height: 400px; overflow-y: auto; font-family: monospace; white-space: pre-wrap; font-size: 13px; line-height: 1.5; }
            .upload-box { border: 2px dashed #64748b; padding: 40px; text-align: center; border-radius: 12px; background: #1e293b; transition: 0.3s; }
            .status-tag { background: #10b981; color: white; padding: 4px 12px; border-radius: 20px; font-size: 12px; }
            button { background: #3b82f6; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="sidebar"><h2>PRIZUX Console</h2><nav><p>🏠 Overview</p><p>🛡️ Security Logs</p><p>📂 File Manager</p></nav></div>
        <div class="main">
            <div style="display:flex; justify-content:space-between; align-items:center;"><h1>Infrastructure Monitoring</h1><span class="status-tag">SYSTEM ONLINE</span></div>
            <div class="card"><h3>Real-time Auth Logs</h3><div id="log-container" class="log-view">로딩 중...</div><div style="margin-top:10px; text-align:right;"><button onclick="fetchLogs()">새로고침</button></div></div>
            <div class="card"><h3>Emergency Patch Upload</h3>
                <form id="upload-form"><div class="upload-box"><input type="file" id="file-input" name="file" style="display:none;"><label for="file-input" style="cursor:pointer;"><div style="font-size:40px;">📤</div><p id="file-name">파일을 선택하세요</p></label></div>
                <div style="margin-top:15px; text-align:right;"><button type="submit">서버로 전송</button></div></form>
            </div>
        </div>
        <script>
            async function fetchLogs() { const res = await fetch('/admin/api/logs'); const data = await res.json(); const logBox = document.getElementById('log-container'); logBox.textContent = data.logs; logBox.scrollTop = logBox.scrollHeight; }
            document.getElementById('file-input').onchange = e => { document.getElementById('file-name').textContent = e.target.files[0].name; };
            document.getElementById('upload-form').onsubmit = async (e) => { e.preventDefault(); const formData = new FormData(); formData.append('file', document.getElementById('file-input').files[0]); const res = await fetch('/admin/api/upload', { method: 'POST', body: formData }); const result = await res.json(); alert(result.detail || "성공"); };
            fetchLogs(); setInterval(fetchLogs, 5000);
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=admin_html)

@app.get("/admin/api/logs")
async def get_logs():
    try:
        if AUTH_LOG_PATH.exists():
            with open(AUTH_LOG_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
                return {"logs": "".join(lines[-100:])}
        return {"logs": "File not found."}
    except Exception as e:
        return {"logs": str(e)}

@app.post("/admin/api/upload")
async def upload_file(file: UploadFile = File(...)):
    save_path = SOC_DIR / file.filename
    try:
        with save_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        return {"ok": True, "detail": f"File {file.filename} saved."}
    except Exception as e:
        return {"ok": False, "detail": str(e)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8888)
