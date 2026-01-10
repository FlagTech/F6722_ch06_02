#!/usr/bin/env python3
"""
檢查提示內容中是否包含敏感資訊的腳本
用於 Cursor beforeSubmitPrompt hook
"""

import json
import re
import sys
from typing import Dict, Any, List, Tuple


def detect_api_key(text: str) -> bool:
    """檢測 API Key 模式"""
    # 常見的 API Key 格式
    patterns = [
        r'[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',  # API_KEY: xxx
        r'[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]\s+([A-Za-z0-9_\-]{20,})',  # API_KEY xxx
        r'sk-[A-Za-z0-9]{32,}',  # OpenAI API Key
        r'AIza[0-9A-Za-z_-]{35}',  # Google API Key
        r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
        r'[0-9a-zA-Z/+]{40}',  # 40 字元的 base64 編碼 key
    ]
    for pattern in patterns:
        if re.search(pattern, text):
            return True
    return False


def detect_password(text: str) -> bool:
    """檢測密碼模式"""
    patterns = [
        r'[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[:=]\s*["\']?([^\s"\']{6,})["\']?',  # password: xxx
        r'[Pp][Ww][Dd]\s*[:=]\s*["\']?([^\s"\']{6,})["\']?',  # pwd: xxx
        r'[Pp]ass\s*[:=]\s*["\']?([^\s"\']{6,})["\']?',  # pass: xxx
        r'密碼\s*[:=]\s*["\']?([^\s"\']{6,})["\']?',  # 密碼: xxx
    ]
    for pattern in patterns:
        if re.search(pattern, text):
            return True
    return False


def detect_secret_key(text: str) -> bool:
    """檢測 Secret Key 模式"""
    patterns = [
        r'[Ss][Ee][Cc][Rr][Ee][Tt]\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',  # SECRET: xxx
        r'[Ss][Ee][Cc][Rr][Ee][Tt][_-]?[Kk][Ee][Yy]\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',  # SECRET_KEY: xxx
        r'[Tt][Oo][Kk][Ee][Nn]\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',  # TOKEN: xxx
    ]
    for pattern in patterns:
        if re.search(pattern, text):
            return True
    return False


def detect_credentials(text: str) -> bool:
    """檢測帳號密碼組合"""
    patterns = [
        r'[Uu][Ss][Ee][Rr][Nn][Aa][Mm][Ee]\s*[:=].*[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[:=]',  # username: ... password: ...
        r'[Aa][Cc][Cc][Oo][Uu][Nn][Tt]\s*[:=].*[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[:=]',  # account: ... password: ...
        r'登入\s*[:=].*密碼\s*[:=]',  # 登入: ... 密碼: ...
    ]
    for pattern in patterns:
        if re.search(pattern, text, re.DOTALL):
            return True
    return False


def detect_email_password(text: str) -> bool:
    """檢測電子郵件和密碼組合"""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    password_pattern = r'[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[:=]\s*["\']?([^\s"\']{6,})["\']?'
    
    if re.search(email_pattern, text) and re.search(password_pattern, text):
        return True
    return False


def check_sensitive_info(prompt: str) -> Tuple[bool, str]:
    """
    檢查提示內容中是否包含敏感資訊
    
    Returns:
        (has_sensitive_info, warning_message)
    """
    checks = [
        (detect_api_key, "檢測到 API Key，請勿在提示中包含 API Key 等敏感資訊"),
        (detect_password, "檢測到密碼資訊，請勿在提示中包含密碼等敏感資訊"),
        (detect_secret_key, "檢測到 Secret Key 或 Token，請勿在提示中包含此類敏感資訊"),
        (detect_credentials, "檢測到帳號密碼組合，請勿在提示中包含帳號密碼等敏感資訊"),
        (detect_email_password, "檢測到電子郵件和密碼組合，請勿在提示中包含此類敏感資訊"),
    ]
    
    for check_func, warning_msg in checks:
        if check_func(prompt):
            return True, warning_msg
    
    return False, ""


def main():
    """主函數：讀取 JSON 輸入，檢查敏感資訊，輸出結果"""
    try:
        # 從 stdin 讀取 UTF-8 編碼的 JSON 資料
        input_data = sys.stdin.buffer.read().decode('utf-8')
        
        # 解析 JSON
        try:
            data: Dict[str, Any] = json.loads(input_data)
        except json.JSONDecodeError as e:
            # JSON 解析失敗，輸出錯誤並允許繼續
            result = {
                "continue": True,
                "user_message": f"JSON 解析錯誤: {str(e)}"
            }
            output = json.dumps(result, ensure_ascii=False)
            sys.stdout.buffer.write(output.encode('utf-8'))
            sys.stdout.buffer.flush()
            return
        
        # 取得 prompt 內容
        prompt = data.get("prompt", "")
        
        if not prompt:
            # 沒有 prompt，允許繼續
            result = {"continue": True}
            output = json.dumps(result, ensure_ascii=False)
            sys.stdout.buffer.write(output.encode('utf-8'))
            sys.stdout.buffer.flush()
            return
        
        # 檢查敏感資訊
        has_sensitive, warning_msg = check_sensitive_info(prompt)
        
        if has_sensitive:
            # 檢測到敏感資訊，阻止提交
            result = {
                "continue": False,
                "user_message": warning_msg
            }
        else:
            # 未檢測到敏感資訊，允許繼續
            result = {"continue": True}
        
        # 輸出 JSON 結果（使用 UTF-8 編碼）
        output = json.dumps(result, ensure_ascii=False)
        sys.stdout.buffer.write(output.encode('utf-8'))
        sys.stdout.buffer.flush()
        
    except Exception as e:
        # 發生未預期的錯誤，輸出錯誤訊息但允許繼續（避免阻擋使用者）
        result = {
            "continue": True,
            "user_message": f"檢查過程中發生錯誤: {str(e)}"
        }
        output = json.dumps(result, ensure_ascii=False)
        sys.stdout.buffer.write(output.encode('utf-8'))
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()

