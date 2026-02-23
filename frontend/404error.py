from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment

app = FastAPI()
env = Environment()

def render_yangdong(source, **context):
    template = env.from_string(source)
    return template.render(**context)

@app.exception_handler(Exception)
@app.exception_handler(404)
async def universal_error_handler(request: Request, exc: Exception):
    invalid_path = request.url.path
    template_source = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SYSTEM CRITICAL ERROR</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
            body {{ background: #000; color: #0f0; font-family: 'Share Tech Mono', monospace; margin: 0; height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; overflow: hidden; }}
            .glitch {{ font-size: 5rem; font-weight: bold; position: relative; color: #fff; text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff, 0.025em 0.04em 0 #fffc00; animation: glitch 725ms infinite; }}
            @keyframes glitch {{ 0% {{ text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff, 0.025em 0.04em 0 #fffc00; }} 50% {{ text-shadow: 0.05em 0.035em 0 #00fffc, 0.03em 0 0 #fc00ff, 0 -0.04em 0 #fffc00; }} 100% {{ text-shadow: -0.05em 0 0 #00fffc, -0.025em -0.025em 0 #fc00ff, -0.025em -0.05em 0 #fffc00; }} }}
            .rick-ascii {{ font-size: 8px; line-height: 8px; white-space: pre; color: rgba(0, 255, 0, 0.5); margin: 20px 0; }}
            .error-msg {{ color: #ff0033; font-size: 1.2rem; text-transform: uppercase; }}
            .path-info {{ background: #111; padding: 5px 15px; border-radius: 5px; color: #2563eb; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="glitch">ERROR</div>
        <p class="error-msg">Critical Protocol Violation Detected</p>
        <p>IDENTIFIED PATH: <span class="path-info">{invalid_path}</span></p>
        <div class="rick-ascii">
    NEVER GONNA GIVE YOU UP
    NEVER GONNA LET YOU DOWN
           _
          / )
   _     ( /
  / \\    / /
 (   )  / /
  \\  \\/ /
   \\    /
    |  |
    |  |
   /    \\
  /      \\
 (________)
        </div>
        <p style="color:#222;">SYSTEM_ROOT_LOGGED_EVENT</p>
    </body>
    </html>
    """
    return HTMLResponse(content=render_yangdong(template_source), status_code=500)

@app.get("/")
async def index():
    return HTMLResponse(content="""
    <body style="background:#000; color:#fff; display:flex; flex-direction:column; justify-content:center; align-items:center; height:100vh; font-family:sans-serif;">
        <h1>PRIZUX CORE ENGINE</h1>
        <p>아무 주소나 쳐서 들어가면 에러 페이지로 튕깁니다.</p>
        <a href="/{{7*7}}" style="color:#2563eb; margin-top:20px;">error  경로</a>
    </body>
    """)
