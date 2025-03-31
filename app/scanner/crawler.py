#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WebShield - Web应用漏洞扫描器
网站爬虫模块 - 负责抓取网站URL和表单
"""

import re
import logging
import urllib.parse
from collections import deque
import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebCrawler:
    """网站爬虫类，负责抓取目标网站的URL和表单"""
    
    def __init__(self, start_url, depth=2, max_urls=100, timeout=10, headers=None):
        """
        初始化爬虫
        
        参数:
            start_url (str): 起始URL
            depth (int): 爬取深度
            max_urls (int): 最大爬取URL数量
            timeout (int): 请求超时时间(秒)
            headers (dict): 请求头
        """
        self.start_url = start_url
        self.depth = depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.headers = headers or {
            'User-Agent': 'WebShield-Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        # 获取基础域名，用于判断是否同域名
        parsed_url = urllib.parse.urlparse(start_url)
        self.base_domain = parsed_url.netloc
        self.base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # 存储已访问的URL
        self.visited_urls = set()
        # 存储发现的表单
        self.forms = []
        # 存储URL和对应的参数
        self.urls_with_params = {}
    
    def crawl(self):
        """
        开始爬取网站
        
        返回:
            dict: 包含发现的URL、表单和URL参数信息
        """
        logger.info(f"开始爬取网站: {self.start_url}")
        
        # 使用队列实现广度优先搜索
        queue = deque([(self.start_url, 0)])  # (url, depth)
        
        while queue and len(self.visited_urls) < self.max_urls:
            url, current_depth = queue.popleft()
            
            # 检查URL是否已访问过
            if url in self.visited_urls:
                continue
            
            # 检查URL是否超出深度限制
            if current_depth > self.depth:
                continue
            
            # 检查是否同域名
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.netloc and parsed_url.netloc != self.base_domain:
                continue
            
            logger.info(f"爬取URL ({current_depth}/{self.depth}): {url}")
            
            try:
                # 发送请求获取页面内容
                response = requests.get(url, headers=self.headers, timeout=self.timeout)
                response.raise_for_status()
                
                # 标记URL为已访问
                self.visited_urls.add(url)
                
                # 分析URL参数
                self._analyze_url_params(url)
                
                # 只处理HTML内容
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    continue
                
                # 解析HTML
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # 提取表单
                self._extract_forms(soup, url)
                
                # 如果已达到最大深度，不再继续提取链接
                if current_depth == self.depth:
                    continue
                
                # 提取链接并加入队列
                for link in self._extract_links(soup, url):
                    if link not in self.visited_urls:
                        queue.append((link, current_depth + 1))
            
            except RequestException as e:
                logger.error(f"请求URL失败: {url}, 错误: {str(e)}")
            except Exception as e:
                logger.error(f"处理URL时出错: {url}, 错误: {str(e)}")
        
        logger.info(f"爬取完成，共发现 {len(self.visited_urls)} 个URL，{len(self.forms)} 个表单")
        
        # 返回爬取结果
        return {
            'urls': list(self.visited_urls),
            'forms': self.forms,
            'urls_with_params': self.urls_with_params
        }
    
    def _extract_links(self, soup, base_url):
        """
        从HTML中提取链接
        
        参数:
            soup (BeautifulSoup): BeautifulSoup对象
            base_url (str): 基础URL，用于解析相对URL
            
        返回:
            list: 提取的链接列表
        """
        links = []
        
        # 查找所有<a>标签
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            
            # 跳过JavaScript链接和锚点
            if href.startswith('javascript:') or href.startswith('#'):
                continue
            
            # 解析URL
            absolute_url = urllib.parse.urljoin(base_url, href)
            
            # 规范化URL，移除片段
            parsed_url = urllib.parse.urlparse(absolute_url)
            normalized_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                parsed_url.query,
                ''  # 移除fragment
            ))
            
            # 只保留HTTP和HTTPS链接
            if normalized_url.startswith(('http://', 'https://')):
                links.append(normalized_url)
        
        return links
    
    def _extract_forms(self, soup, page_url):
        """
        从HTML中提取表单
        
        参数:
            soup (BeautifulSoup): BeautifulSoup对象
            page_url (str): 页面URL
        """
        forms = soup.find_all('form')
        
        for form in forms:
            form_data = {
                'page_url': page_url,
                'action': urllib.parse.urljoin(page_url, form.get('action', '')),
                'method': form.get('method', 'get').lower(),
                'inputs': []
            }
            
            # 提取所有输入字段
            for input_field in form.find_all(['input', 'select', 'textarea']):
                field_type = input_field.name
                
                if field_type == 'input':
                    field_type = input_field.get('type', 'text')
                
                field_data = {
                    'name': input_field.get('name', ''),
                    'type': field_type,
                    'value': input_field.get('value', '')
                }
                
                if field_data['name']:  # 只保存有name的字段
                    form_data['inputs'].append(field_data)
            
            self.forms.append(form_data)
    
    def _analyze_url_params(self, url):
        """
        分析URL参数
        
        参数:
            url (str): 要分析的URL
        """
        parsed = urllib.parse.urlparse(url)
        
        # 如果URL有查询参数
        if parsed.query:
            # 获取没有参数的基础URL
            base_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                '',
                ''
            ))
            
            # 解析查询参数
            query_params = urllib.parse.parse_qs(parsed.query)
            param_names = list(query_params.keys())
            
            # 存储URL和参数信息
            if base_url not in self.urls_with_params:
                self.urls_with_params[base_url] = []
            
            # 确保不重复添加相同的参数
            if param_names not in self.urls_with_params[base_url]:
                self.urls_with_params[base_url].append(param_names) 