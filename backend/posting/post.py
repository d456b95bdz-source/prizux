from fastapi import APIRouter, Request, Query

from fastapi.responses import HTMLResponse

from jinja2 import Environment



router = APIRouter()



@router.get("/post", response_class=HTMLResponse)

async def get_post_detail(request: Request, id: str = Query("1")):

    template_content = f"""

    <!DOCTYPE html>

    <html lang="ko">

    <head>

        <meta charset="UTF-8">

        <title>Prizux AI | Future Insight #{id}</title>

        <style>

            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Noto+Sans+KR:wght@300;500&display=swap');

            

            body {{ 

                margin: 0; padding: 0; background-color: #000;

                display: flex; justify-content: center; align-items: center; height: 100vh;

                overflow: hidden; color: #fff; font-family: 'Noto Sans KR', sans-serif;

            }}



            .beams-container {{

                width: 1080px; height: 1080px; position: absolute;

                top: 50%; left: 50%; transform: translate(-50%, -50%) rotate(30deg);

                z-index: 1; pointer-events: none;

            }}



            .beam {{

                position: absolute; width: 2px; height: 300px;

                background: linear-gradient(to bottom, transparent, #ffffff, transparent);

                opacity: 0;

                animation: flow 4s infinite linear;

            }}



    

            .beam:nth-child(1) {{ left: 20%; animation-delay: 0s; }}

            .beam:nth-child(2) {{ left: 40%; animation-delay: 1.5s; }}

            .beam:nth-child(3) {{ left: 60%; animation-delay: 0.8s; }}

            .beam:nth-child(4) {{ left: 80%; animation-delay: 2.2s; }}



            @keyframes flow {{

                0% {{ transform: translateY(-1000px); opacity: 0; }}

                50% {{ opacity: 0.5; }}

                100% {{ transform: translateY(1000px); opacity: 0; }}

            }}



            .glass-card {{

                position: relative; z-index: 2;

                background: rgba(0, 0, 0, 0.7);

                border: 1px solid rgba(255, 255, 255, 0.1);

                padding: 50px; border-radius: 30px;

                backdrop-filter: blur(20px);

                box-shadow: 0 0 60px rgba(255, 255, 255, 0.05);

                text-align: center; max-width: 550px;

            }}



            h1 {{ 

                font-family: 'Orbitron', sans-serif; color: #fff; 

                letter-spacing: 8px; text-shadow: 0 0 15px rgba(255, 255, 255, 0.3);

            }}



            .id-badge {{

                background: #fff; color: #000; padding: 3px 15px;

                font-weight: bold; border-radius: 4px; font-size: 0.75rem; 

                display: inline-block; margin-bottom: 20px;

            }}

        </style>

    </head>

    <body>

        <div class="beams-container">

            <div class="beam"></div>

            <div class="beam"></div>

            <div class="beam"></div>

            <div class="beam"></div>

            <div style="width:100%; height:100%; border:1px solid rgba(255,255,255,0.05);"></div>

        </div>



        <div class="glass-card">

            <div class="id-badge">NEURAL LINK #{id}</div>

            <h1>PRIZUX</h1>

            <div class="quote" style="font-size: 1.1rem; color: #ccc; border-left: 2px solid #fff; padding-left: 20px; text-align: left; margin-top: 20px;">

                "Prizux AI를 사용하는 순간,<br>당신은 단순한 그래프를 보는 것이 아닙니다.<br>

                <strong>데이터의 파편 너머에 숨겨진 '미래'를 보게 됩니다.</strong>"

            </div>

        </div>

    </body>

    </html>

    """

    env = Environment()

    template = env.from_string(template_content)

    return template.render()
