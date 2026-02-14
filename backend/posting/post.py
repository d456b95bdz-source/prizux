from flask import Flask, request, render_template_string



app = Flask(__name__)



@app.route('/post.html')

def post_detail():

    post_id = request.args.get('id', '1')



  

    template_content = f"""

    <!DOCTYPE html>

    <html lang="ko">

    <head>

        <meta charset="UTF-8">

        <title>Prizux AI | Future Insight #{post_id}</title>

        <style>

            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Noto+Sans+KR:wght@300;500&display=swap');

            

            body {{ 

                margin: 0; padding: 0; background-color: #000;

                display: flex; justify-content: center; align-items: center; height: 100vh;

                overflow: hidden; color: #fff; font-family: 'Noto Sans KR', sans-serif;

            }}



            

            .beams-container {{

                width: 1080px; height: 1080px; position: absolute;

                top: 50%; left: 50%; transform: translate(-50%, -50%);

                z-index: 1; pointer-events: none;

                opacity: 0.6; 

            }}



            .glass-card {{

                position: relative; z-index: 2; /* 빔 위로 올라오게 */

                background: rgba(0, 0, 0, 0.6);

                border: 1px solid rgba(255, 255, 255, 0.1);

                padding: 50px; border-radius: 30px;

                backdrop-filter: blur(20px);

                box-shadow: 0 0 60px rgba(255, 255, 255, 0.05);

                text-align: center; max-width: 550px;

            }}



            h1 {{ 

                font-family: 'Orbitron', sans-serif; color: #fff; 

                letter-spacing: 8px; margin-bottom: 5px;

                text-shadow: 0 0 15px rgba(255, 255, 255, 0.3);

            }}



            .id-badge {{

                background: #fff; color: #000; padding: 3px 15px;

                font-weight: bold; border-radius: 4px; font-size: 0.75rem; 

                display: inline-block; margin-bottom: 20px;

            }}



            .quote {{

                font-size: 1.1rem; color: #ccc; margin-top: 35px;

                line-height: 1.8; border-left: 2px solid #fff; padding-left: 20px; text-align: left;

            }}



            strong {{ color: #fff; text-shadow: 0 0 5px #fff; }}

        </style>

    </head>

    <body>

        <div class="beams-container">

            <div style="width:100%; height:100%; border:1px dashed rgba(255,255,255,0.1); transform: rotate(30deg);"></div>

        </div>



        <div class="glass-card">

            <div class="id-badge">NEURAL LINK #{post_id}</div>

            <h1>PRIZUX</h1>

            <p style="letter-spacing: 3px; color: #666; font-size: 0.9rem;">FUTURE ANALYSIS ENGINE</p>

            

            <div class="quote">

                "Prizux AI를 사용하는 순간,<br>당신은 단순한 그래프를 보는 것이 아닙니다.<br>

                <strong>데이터의 파편 너머에 숨겨진 '미래'를 보게 됩니다.</strong>"

            </div>

        </div>

    </body>

    </html>

    """



    return render_template_string(template_content)



if __name__ == '__main__':

    app.run(host='0.0.0.0', port=8080)
