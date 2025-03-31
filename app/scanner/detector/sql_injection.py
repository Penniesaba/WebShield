#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WebShield - Web应用漏洞扫描器
SQL注入漏洞检测模块
"""

import logging
import urllib.parse
import re
import requests
from bs4 import BeautifulSoup

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SQLInjectionDetector:
    """SQL注入漏洞检测类"""
    
    def __init__(self, timeout=10, headers=None):
        """
        初始化SQL注入检测器
        
        参数:
            timeout (int): 请求超时时间(秒)
            headers (dict): 请求头
        """
        self.timeout = timeout
        self.headers = headers or {
            'User-Agent': 'WebShield-Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        # SQL注入测试向量
        self.sql_injection_payloads = [
            "' OR '1'='1", 
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR '1'='1' #",
            "' OR 1=1 --",
            "' OR 1=1 /*",
            "\" OR \"\"=\"",
            "\" OR 1=1 --",
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT NULL,NULL,NULL --",
            "' AND 1=1 --",
            "' AND 1=2 --",
            "' OR 'x'='x",
            "\" OR \"x\"=\"x",
            "' AND (SELECT 1 FROM DUAL) --",
            "' AND 7659=7659 --",
            "' AND 7659=7658 --",
            "' WAITFOR DELAY '0:0:5' --",
            "1; WAITFOR DELAY '0:0:5' --"
        ]
        
        # SQL错误关键词
        self.sql_error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysqli",
            r"PostgreSQL.*?ERROR",
            r"Oracle.*?ORA-[0-9]",
            r"Microsoft SQL Server.*?[0-9a-fA-F]{8}",
            r"ODBC Driver.*?SQL Server",
            r"SQLite3::query",
            r"Warning.*?\Woci_",
            r"Syntax error.*?SQL",
            r"SQLite\/JDBCDriver",
            r"SQL command not properly ended",
            r"DB2 SQL error",
            r"Sybase message",
            r"JET Database Engine",
            r"Incorrect syntax near",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
            r"You have an error in your SQL syntax",
            r"Division by zero in SQL statement",
            r"SQLSTATE\[\d+\]",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unexpected end of command in statement"
        ]
        
    def scan_urls(self, crawler_results):
        """
        扫描URL列表，检测SQL注入漏洞
        
        参数:
            crawler_results (dict): 爬虫结果，包含URLs和表单
            
        返回:
            list: 检测到的SQL注入漏洞列表
        """
        vulnerabilities = []
        
        # 检查URL参数
        if 'urls_with_params' in crawler_results:
            for base_url, param_lists in crawler_results['urls_with_params'].items():
                for param_list in param_lists:
                    # 构建测试URL
                    for param in param_list:
                        for payload in self.sql_injection_payloads:
                            # 测试单个参数
                            test_params = {p: 'test' for p in param_list}
                            test_params[param] = payload
                            
                            # 构建测试URL
                            test_url = f"{base_url}?{urllib.parse.urlencode(test_params)}"
                            
                            # 测试注入
                            vulnerability = self._test_sql_injection(test_url, param, payload)
                            if vulnerability:
                                vulnerabilities.append(vulnerability)
                                # 一旦发现参数存在漏洞，就停止测试该参数的其他Payload
                                break
        
        # 检查表单
        if 'forms' in crawler_results:
            for form in crawler_results.get('forms', []):
                vulnerabilities.extend(self._test_form(form))
        
        return vulnerabilities
    
    def _test_sql_injection(self, url, param=None, payload=None, data=None, method='GET'):
        """
        测试单个URL或表单是否存在SQL注入漏洞
        
        参数:
            url (str): 要测试的URL
            param (str, optional): 被测试的参数名
            payload (str, optional): 被注入的Payload
            data (dict, optional): POST数据
            method (str): 请求方法，GET或POST
            
        返回:
            dict: 如果存在漏洞，返回漏洞信息；否则返回None
        """
        try:
            logger.info(f"测试SQL注入: {url}, 参数: {param}, Payload: {payload}")
            
            if method.upper() == 'GET':
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    timeout=self.timeout,
                    allow_redirects=False
                )
            else:
                response = requests.post(
                    url, 
                    data=data, 
                    headers=self.headers, 
                    timeout=self.timeout,
                    allow_redirects=False
                )
            
            # 检查响应中是否包含SQL错误
            for pattern in self.sql_error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return {
                        'type': 'sql_injection',
                        'url': url,
                        'method': method,
                        'param': param,
                        'payload': payload,
                        'evidence': pattern,
                        'risk': 'high',
                        'confidence': 'medium'
                    }
            
            # 检查时间盲注（这里简化处理，实际应用需要更复杂的逻辑）
            if 'WAITFOR DELAY' in payload and response.elapsed.total_seconds() > 5:
                return {
                    'type': 'sql_injection',
                    'url': url,
                    'method': method,
                    'param': param,
                    'payload': payload,
                    'evidence': f"时间延迟检测: {response.elapsed.total_seconds()}秒",
                    'risk': 'high',
                    'confidence': 'medium'
                }
            
            # 检查布尔盲注（这里简化处理）
            if ('AND 7659=7659' in payload and '7659=7658' not in payload) and 'login successful' in response.text.lower():
                return {
                    'type': 'sql_injection',
                    'url': url,
                    'method': method,
                    'param': param,
                    'payload': payload,
                    'evidence': "布尔盲注检测",
                    'risk': 'high',
                    'confidence': 'medium'
                }
                
        except Exception as e:
            logger.error(f"测试SQL注入时出错: {url}, 错误: {str(e)}")
        
        return None
    
    def _test_form(self, form):
        """
        测试表单是否存在SQL注入漏洞
        
        参数:
            form (dict): 表单信息
            
        返回:
            list: 检测到的SQL注入漏洞列表
        """
        vulnerabilities = []
        
        try:
            action_url = form['action']
            method = form['method'].upper()
            
            # 对每个输入字段进行测试
            for input_field in form['inputs']:
                field_name = input_field['name']
                field_type = input_field['type']
                
                # 跳过类型为submit、button、image的字段
                if field_type in ['submit', 'button', 'image', 'reset', 'file']:
                    continue
                
                # 为其他字段创建基本数据
                for payload in self.sql_injection_payloads:
                    # 创建测试数据
                    test_data = {}
                    for inp in form['inputs']:
                        # 对非测试字段使用默认值
                        if inp['name'] != field_name:
                            if inp['type'] in ['submit', 'button', 'image', 'reset']:
                                continue
                            elif inp['type'] == 'checkbox':
                                test_data[inp['name']] = 'on'
                            else:
                                test_data[inp['name']] = inp['value'] or 'test'
                    
                    # 设置测试字段的值为Payload
                    test_data[field_name] = payload
                    
                    # 执行测试
                    if method == 'GET':
                        # 对于GET请求，将表单数据附加到URL中
                        test_url = f"{action_url}?{urllib.parse.urlencode(test_data)}"
                        vulnerability = self._test_sql_injection(test_url, field_name, payload, method='GET')
                    else:
                        # 对于POST请求，将表单数据放在请求体中
                        vulnerability = self._test_sql_injection(action_url, field_name, payload, data=test_data, method='POST')
                    
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        break  # 发现漏洞后停止测试该字段的其他Payload
        
        except Exception as e:
            logger.error(f"测试表单SQL注入时出错: {form.get('action', '')}, 错误: {str(e)}")
        
        return vulnerabilities 