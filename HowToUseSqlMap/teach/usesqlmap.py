#!/usr/bin/env python3
import argparse
import os

def show_usage_u():
    print("""
参数 -u (--url) 用于指定目标 URL，是 sqlmap 的核心参数之一。
例如：
  sqlmap -u "http://127.0.0.1/vuln.php?id=1" --batch

演示（假设本地有测试环境）：
  尝试连接 http://127.0.0.1/test?id=1
  模拟命令执行：
    sqlmap -u "http://127.0.0.1/test?id=1" --batch --level=1 --risk=1
""")

def main():
    parser = argparse.ArgumentParser(description="SQLMap 使用助手脚本")
    parser.add_argument('-u', '--url', nargs='?', const=True, help='展示 -u 参数用法并模拟本地测试')
    
    args = parser.parse_args()

    if args.url:
        show_usage_u()
        # 如果你本地装了sqlmap，可以实际调用它试试：
        # cmd = 'python3 /opt/sqlmap/sqlmap.py -u "http://127.0.0.1/test?id=1" --batch --level=1 --risk=1'
        # os.system(cmd)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
