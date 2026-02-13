from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment

router = APIRouter()

@router.get("/post.html", response_class=HTMLResponse)
async def get_post_detail(request: Request, id: str = "1"):
    """
    양동적임 ㄹㅇ ㅋㅋㅋㅋ AI 모델 분석 리포트 페이지 뼈대 잡아봤어. 
    네가 나중에 CSS 더 만져주면 진짜 지릴 듯 ㅋㅋㅋ
    """
    
    # 간지 끝판왕 예상 ㅋㅋㅋㅋ
    template_content = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>Prizux AI | Insight Report #{id}</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Noto+Sans+KR:wght@300;500&display=swap');
            body {{ 
                background-color: #050505; color: #e0e0e0; 
                font-family: 'Noto Sans KR', sans-serif; margin: 0; padding: 0;
                overflow: hidden;
            }}
            .container {{
                height: 100vh; display: flex; flex-direction: column;
                justify-content: center; align-items: center;
                background: radial-gradient(circle at center, #111 0%, #000 100%);
            }}
            .glass-card {{
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid rgba(0, 255, 170, 0.2);
                padding: 40px; border-radius: 20px;
                backdrop-filter: blur(10px); box-shadow: 0 0 40px rgba(0, 255, 170, 0.1);
                text-align: center; max-width: 600px;
            }}
            h1 {{ 
                font-family: 'Orbitron', sans-serif; color: #00ffaa; 
                letter-spacing: 5px; margin-bottom: 10px;
                text-shadow: 0 0 10px rgba(0, 255, 170, 0.5);
            }}
            .id-badge {{
                background: #00ffaa; color: #000; padding: 2px 12px;
                font-weight: bold; border-radius: 5px; font-size: 0.8rem;
            }}
            .quote {{
                font-style: italic; color: #888; margin-top: 30px;
                line-height: 1.6; border-left: 3px solid #00ffaa; padding-left: 15px;
            }}
            .footer {{
                margin-top: 40px; font-size: 0.7rem; color: #444; text-transform: uppercase;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="glass-card">
                <div class="id-badge">REPORT DATA #{id}</div>
                <h1>PRIZUX DEEPCORE</h1>
                <p style="font-size: 1.2rem; font-weight: 300;">
                    Numerical Intelligence Model v4.2 Analysis
                </p>
                
                <div class="quote">
                    "Prizux AI를 사용하는 순간, 당신은 단순한 그래프를 보는 것이 아닙니다.<br>
                    <strong>데이터의 파편 너머에 숨겨진 '미래'를 보게 됩니다.</strong>"
                </div>

                <div class="footer">
                    Neural Synapse Synchronized | Connection Stable | UID: {id}
                </div>
            </div>
        </div>
    </body>
    </html>
    """
 
    env = Environment()
    template = env.from_string(template_content)

    return template.render()
