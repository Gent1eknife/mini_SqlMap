import sys
import requests
# 忽略SSL证书验证警告
requests.packages.urllib3.disable_warnings()
from lib.core.scanner import Scanner
from lib.core.xml_parser import XMLParser

def main():
    # 检查命令行参数是否足够
    if len(sys.argv) < 2:
        print("Usage: python mini_sqlmap.py <url>")
        return

    url = sys.argv[1]  # 获取目标URL
    parser = XMLParser()  # 初始化XML解析器，加载测试数据
    scanner = Scanner(url, parser)  # 初始化扫描器，传入URL和解析器

    # 检测SQL注入
    scanner.detect_injection()

if __name__ == "__main__":  # 判断是否作为主程序运行
    main()  # 调用主函数