import requests

def send_request(url):
    """发送 HTTP 请求并返回响应内容"""
    try:
        # 添加 verify=False 参数以禁用SSL证书验证（仅测试环境使用）
        response = requests.get(url, timeout=10, verify=False)
        return response.text
    except requests.RequestException as e:
        print(f"[-] Error sending request: {e}")
        return ""