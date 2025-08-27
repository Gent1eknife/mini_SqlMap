import os
import xml.etree.ElementTree as ET
import random

class XMLParser:
    def __init__(self):
        self.payloads = {}
        self.queries = None
        self._load_payloads()
        self._load_queries()

    def _load_payloads(self):
        payload_dir = os.path.join(os.path.dirname(__file__), "..", "..", "data", "xml", "payloads")
        if not os.path.exists(payload_dir):
            print(f"[-] Payload directory not found: {payload_dir}")
            return

        for filename in os.listdir(payload_dir):
            if filename.endswith(".xml"):
                file_path = os.path.join(payload_dir, filename)
                try:
                    tree = ET.parse(file_path)
                    root = tree.getroot()
                    self.payloads[filename.split(".")[0]] = root
                except ET.ParseError as e:
                    print(f"[-] Error parsing {file_path}: {e}")

    def _load_queries(self):
        queries_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "xml", "queries.xml")
        if not os.path.exists(queries_path):
            print(f"[-] Queries file not found: {queries_path}")
            # 创建一个空的根元素，避免后续代码崩溃
            self.queries = ET.Element("root")
            return

        try:
            tree = ET.parse(queries_path)
            root = tree.getroot()
            self.queries = root
        except ET.ParseError as e:
            print(f"[-] Error parsing {queries_path}: {e}")
            self.queries = ET.Element("root")

    def get_payloads(self, payload_type):
        return self.payloads.get(payload_type, None)

    def get_queries(self, dbms):
        if self.queries is None:
            return None
        
        for db in self.queries.findall("dbms"):
            if db.get("value") == dbms:
                return db
        return None

    def replace_placeholders(self, payload, char_type='NULL', col_start=1, col_stop=10):
        """替换 payload 中的占位符"""
        # 替换字符类型占位符
        payload = payload.replace('[CHAR]', char_type)

        # 替换列范围占位符
        payload = payload.replace('[COLSTART]', str(col_start))
        payload = payload.replace('[COLSTOP]', str(col_stop))

        # 替换 UNION 占位符
        payload = payload.replace('[UNION]', 'UNION ALL SELECT')

        # 替换 SQL 注释占位符
        payload = payload.replace('[GENERIC_SQL_COMMENT]', '-- ')

        # 替换随机数占位符
        while '[RANDNUM]' in payload:
            payload = payload.replace('[RANDNUM]', str(random.randint(1, 10000)), 1)

        return payload
        