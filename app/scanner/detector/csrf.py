#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WebShield - Web应用漏洞扫描器
CSRF(跨站请求伪造)漏洞检测模块
"""

import logging
import re
import requests
from bs4 import BeautifulSoup

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CSRFDetector:
    """CSRF(跨站请求伪造)漏洞检测类"""
    
    def __init__(self, timeout=10, headers=None):
        """
        初始化CSRF检测器
        
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
    
    def scan_urls(self, crawler_results):
        """
        扫描URL列表，检测CSRF漏洞
        
        参数:
            crawler_results (dict): 爬虫结果，包含URLs和表单
            
        返回:
            list: 检测到的CSRF漏洞列表
        """
        vulnerabilities = []
        
        # CSRF主要检查表单
        if 'forms' in crawler_results:
            for form in crawler_results.get('forms', []):
                vulnerability = self._test_form(form)
                if vulnerability:
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _test_form(self, form):
        """
        测试表单是否存在CSRF漏洞
        
        参数:
            form (dict): 表单信息
            
        返回:
            dict: 如果存在漏洞，返回漏洞信息；否则返回None
        """
        try:
            # 只检测POST表单，因为GET表单通常不会执行敏感操作
            if form['method'].upper() != 'POST':
                return None
            
            action_url = form['action']
            page_url = form['page_url']
            
            logger.info(f"测试CSRF: {action_url}, 页面: {page_url}")
            
            # 获取表单所在页面
            response = requests.get(
                page_url,
                headers=self.headers,
                timeout=self.timeout
            )
            
            # 解析页面内容
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 查找CSRF令牌
            csrf_found = False
            
            # 检查表单中是否有CSRF令牌字段
            for input_field in form['inputs']:
                input_name = input_field['name'].lower()
                # 常见的CSRF令牌字段名
                csrf_field_names = [
                    'csrf', 'xsrf', '_csrf', '_token', 'token', 'csrf_token', 
                    'xsrf_token', 'authenticity_token', 'anti-forgery',
                    'csrfmiddlewaretoken', 'anti-csrf', 'request_token'
                ]
                
                for csrf_name in csrf_field_names:
                    if csrf_name in input_name:
                        csrf_found = True
                        break
                
                if csrf_found:
                    break
            
            # 检查HTTP头中是否有CSRF保护
            headers_to_check = [
                'X-CSRF-Token', 'X-XSRF-Token', 'X-CSRFToken', 'X-RequestToken',
                'X-Request-Token', 'Anti-CSRF-Token', 'CSRF-Token', 'XSRF-TOKEN'
            ]
            
            for header in headers_to_check:
                if header.lower() in map(str.lower, response.headers.keys()):
                    csrf_found = True
                    break
            
            # 检查Cookie中是否包含CSRF令牌
            if response.cookies:
                cookie_names = [c.name.lower() for c in response.cookies]
                for csrf_name in ['csrf', 'xsrf', '_csrf', 'token', 'csrf_token']:
                    if any(csrf_name in cookie_name for cookie_name in cookie_names):
                        csrf_found = True
                        break
            
            # 检查页面中是否有meta标签中的CSRF令牌
            meta_tags = soup.find_all('meta')
            for meta in meta_tags:
                if meta.get('name') and 'csrf' in meta.get('name').lower():
                    csrf_found = True
                    break
            
            # 检查是否有相关的JavaScript防护
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string and any(term in script.string.lower() for term in ['csrf', 'xsrf', 'token']):
                    csrf_found = True
                    break
            
            # 判断是否存在漏洞
            if not csrf_found:
                # 检查此表单是否可能执行敏感操作
                sensitive_action = self._is_sensitive_operation(form)
                
                if sensitive_action:
                    return {
                        'type': 'csrf',
                        'url': action_url,
                        'method': 'POST',
                        'form_action': action_url,
                        'evidence': "没有发现CSRF令牌或其他保护机制",
                        'sensitive_operation': sensitive_action,
                        'risk': 'medium',
                        'confidence': 'medium'
                    }
        
        except Exception as e:
            logger.error(f"测试CSRF时出错: {form.get('action', '')}, 错误: {str(e)}")
        
        return None
    
    def _is_sensitive_operation(self, form):
        """
        判断表单是否执行敏感操作
        
        参数:
            form (dict): 表单信息
            
        返回:
            str: 如果是敏感操作，返回操作类型；否则返回None
        """
        # 检查表单URL和字段名
        action_url = form['action'].lower()
        
        # 敏感操作关键词
        sensitive_keywords = {
            'user': '用户管理',
            'login': '登录',
            'register': '注册',
            'password': '密码修改',
            'account': '账户管理',
            'profile': '个人资料',
            'admin': '管理员操作',
            'delete': '删除操作',
            'update': '更新操作',
            'transfer': '转账',
            'payment': '支付',
            'checkout': '结账',
            'purchase': '购买',
            'order': '订单',
            'comment': '评论'
        }
        
        # 检查URL是否包含敏感关键词
        for keyword, operation in sensitive_keywords.items():
            if keyword in action_url:
                return operation
        
        # 检查表单字段是否包含敏感关键词
        for input_field in form['inputs']:
            field_name = input_field['name'].lower()
            for keyword, operation in sensitive_keywords.items():
                if keyword in field_name:
                    return operation
        
        # 检查是否含有密码字段，这表明是敏感操作
        password_fields = ['password', 'pwd', 'pass']
        for input_field in form['inputs']:
            if input_field['type'] == 'password' or any(pw in input_field['name'].lower() for pw in password_fields):
                return '密码相关操作'
        
        return None 