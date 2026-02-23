import time
import subprocess

log_file = "/home/prizux/prizux/backend/SoC/access.log"

print("SOC 커스텀 에이전트 가동 시작...")

def follow(thefile):
    thefile.seek(0, 2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

with open(log_file, "r") as f:
    for line in follow(f):
        # 여기서 대시보드 서버로 데이터를 전송하는 로직이 필요합니다.
        # 만약 대시보드가 특정 포트를 열고 있다면 curl 등으로 쏠 수 있습니다.
        print(f"전송 중: {line.strip()}")
        # 예시: subprocess.run(["curl", "-X", "POST", "http://대시보드IP:포트", "-d", line])
