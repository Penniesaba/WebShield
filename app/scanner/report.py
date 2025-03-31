#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WebShield - Web应用漏洞扫描器
漏洞报告生成模块
"""

import os
import json
import logging
from datetime import datetime
import hashlib
from flask import current_app

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilityReportGenerator:
    """漏洞报告生成器"""
    
    def __init__(self, scan_id, target_url, vulnerabilities):
        """
        初始化报告生成器
        
        参数:
            scan_id (str): 扫描ID
            target_url (str): 目标URL
            vulnerabilities (list): 检测到的漏洞列表
        """
        self.scan_id = scan_id
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities
        self.report_time = datetime.now()
    
    def generate_report(self):
        """
        生成漏洞报告
        
        返回:
            str: 报告文件路径
        """
        # 计算风险评分
        risk_score = self._calculate_risk_score()
        
        # 生成HTML报告
        html_report = self._generate_html_report(risk_score)
        
        # 保存报告
        report_path = os.path.join(current_app.config['REPORTS_DIR'], f"{self.scan_id}.html")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        logger.info(f"漏洞报告已生成: {report_path}")
        
        return report_path
    
    def _calculate_risk_score(self):
        """
        计算总体风险评分
        
        返回:
            dict: 风险评分信息
        """
        # 漏洞风险权重
        risk_weights = {
            'high': 10,
            'medium': 5,
            'low': 1
        }
        
        # 漏洞类型权重
        type_weights = {
            'sql_injection': 1.5,  # SQL注入威胁最大
            'xss': 1.2,            # XSS危害次之
            'csrf': 1.0            # CSRF相对危害较低
        }
        
        # 统计各类漏洞数量
        vuln_counts = {
            'sql_injection': 0,
            'xss': 0,
            'csrf': 0,
            'other': 0
        }
        
        # 统计各风险等级漏洞数量
        risk_counts = {
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        # 计算原始分数
        raw_score = 0
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', 'other')
            risk_level = vuln.get('risk', 'medium')
            
            # 更新统计
            if vuln_type in vuln_counts:
                vuln_counts[vuln_type] += 1
            else:
                vuln_counts['other'] += 1
            
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
            
            # 计算此漏洞的分数
            type_weight = type_weights.get(vuln_type, 1.0)
            risk_weight = risk_weights.get(risk_level, 3)
            vuln_score = type_weight * risk_weight
            
            raw_score += vuln_score
        
        # 总漏洞数量
        total_vulns = len(self.vulnerabilities)
        
        # 归一化分数到0-100
        normalized_score = min(100, raw_score * 2) if total_vulns > 0 else 0
        
        # 确定风险等级
        risk_level = 'Low'
        if normalized_score >= 80:
            risk_level = 'Critical'
        elif normalized_score >= 60:
            risk_level = 'High'
        elif normalized_score >= 30:
            risk_level = 'Medium'
        elif normalized_score > 0:
            risk_level = 'Low'
        else:
            risk_level = 'Safe'
        
        return {
            'score': normalized_score,
            'level': risk_level,
            'total_vulnerabilities': total_vulns,
            'vulnerability_counts': vuln_counts,
            'risk_counts': risk_counts
        }
    
    def _generate_html_report(self, risk_score):
        """
        生成HTML格式报告
        
        参数:
            risk_score (dict): 风险评分信息
            
        返回:
            str: HTML报告内容
        """
        # 获取当前时间
        timestamp = self.report_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # HTML头部
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebShield 安全扫描报告 - {self.target_url}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            padding: 20px 0;
            border-bottom: 1px solid #eee;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            color: #2c3e50;
        }}
        .header p {{
            color: #7f8c8d;
            margin: 10px 0 0;
        }}
        .summary {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 5px solid #4285f4;
        }}
        .score-container {{
            display: flex;
            align-items: center;
            margin-top: 15px;
        }}
        .score {{
            width: 100px;
            height: 100px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            font-weight: bold;
            color: white;
            margin-right: 20px;
        }}
        .score-metrics {{
            flex: 1;
        }}
        .stats {{
            display: flex;
            flex-wrap: wrap;
            margin: 20px 0;
        }}
        .stat-box {{
            flex: 1;
            min-width: 200px;
            background-color: #fff;
            border-radius: 5px;
            padding: 15px;
            margin: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .stat-box h3 {{
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
            font-size: 16px;
        }}
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 30px 0;
        }}
        .vuln-table th, .vuln-table td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e1e1e1;
        }}
        .vuln-table th {{
            background-color: #f8f9fa;
            font-weight: 600;
        }}
        .vuln-table tr:hover {{
            background-color: #f8f9fa;
        }}
        .risk-high {{
            color: #d9534f;
            background-color: #d9534f26;
        }}
        .risk-medium {{
            color: #f0ad4e;
            background-color: #f0ad4e26;
        }}
        .risk-low {{
            color: #5bc0de;
            background-color: #5bc0de26;
        }}
        .score-critical {{
            background-color: #d9534f;
        }}
        .score-high {{
            background-color: #f0ad4e;
        }}
        .score-medium {{
            background-color: #5bc0de;
        }}
        .score-low {{
            background-color: #5cb85c;
        }}
        .score-safe {{
            background-color: #5cb85c;
        }}
        .details {{
            margin-top: 10px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
            font-family: monospace;
            white-space: pre-wrap;
            color: #555;
        }}
        .collapsible {{
            background-color: #f8f9fa;
            color: #444;
            cursor: pointer;
            padding: 18px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 15px;
            border-radius: 5px;
            margin-bottom: 5px;
            transition: 0.4s;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .active, .collapsible:hover {{
            background-color: #e9ecef;
        }}
        .collapsible:after {{
            content: '+';
            font-size: 20px;
            color: #777;
        }}
        .active:after {{
            content: '-';
        }}
        .content {{
            padding: 0 18px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.2s ease-out;
            background-color: white;
            border-radius: 0 0 5px 5px;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #7f8c8d;
        }}
        .recommendations {{
            margin-top: 30px;
            padding: 20px;
            background-color: #e8f4f8;
            border-radius: 5px;
            border-left: 5px solid #5bc0de;
        }}
        .recommendations ul {{
            padding-left: 20px;
        }}
        .recommendations li {{
            margin-bottom: 10px;
        }}
        @media (max-width: 768px) {{
            .score-container {{
                flex-direction: column;
                align-items: flex-start;
            }}
            .score {{
                margin-bottom: 20px;
            }}
            .stat-box {{
                min-width: 100%;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WebShield 网站安全漏洞扫描报告</h1>
            <p>扫描目标: {self.target_url}</p>
            <p>扫描时间: {timestamp}</p>
            <p>扫描ID: {self.scan_id}</p>
        </div>

        <div class="summary">
            <h2>扫描结果摘要</h2>
            <div class="score-container">
                <div class="score score-{risk_score['level'].lower()}">
                    {round(risk_score['score'])}
                </div>
                <div class="score-metrics">
                    <h3>安全风险等级: {self._get_risk_level_chinese(risk_score['level'])}</h3>
                    <p>总体风险评分: {round(risk_score['score'], 1)}/100</p>
                    <p>发现漏洞数量: {risk_score['total_vulnerabilities']}</p>
                    <p>高危漏洞: {risk_score['risk_counts']['high']} | 中危漏洞: {risk_score['risk_counts']['medium']} | 低危漏洞: {risk_score['risk_counts']['low']}</p>
                </div>
            </div>
        </div>

        <div class="stats">
            <div class="stat-box">
                <h3>SQL注入漏洞</h3>
                <p>{risk_score['vulnerability_counts']['sql_injection']} 个</p>
            </div>
            <div class="stat-box">
                <h3>XSS跨站脚本漏洞</h3>
                <p>{risk_score['vulnerability_counts']['xss']} 个</p>
            </div>
            <div class="stat-box">
                <h3>CSRF跨站请求伪造漏洞</h3>
                <p>{risk_score['vulnerability_counts']['csrf']} 个</p>
            </div>
            <div class="stat-box">
                <h3>其他漏洞</h3>
                <p>{risk_score['vulnerability_counts']['other']} 个</p>
            </div>
        </div>
"""

        # 如果有漏洞，添加漏洞详情
        if self.vulnerabilities:
            html += """
        <h2>漏洞详情</h2>
"""
            
            # 按风险等级对漏洞进行排序
            risk_order = {'high': 1, 'medium': 2, 'low': 3}
            sorted_vulns = sorted(
                self.vulnerabilities, 
                key=lambda x: (risk_order.get(x.get('risk', 'medium'), 999), x.get('type', ''))
            )
            
            # 添加漏洞详情
            for i, vuln in enumerate(sorted_vulns):
                vuln_type = vuln.get('type', 'unknown')
                risk = vuln.get('risk', 'medium')
                vuln_id = f"vuln-{i+1}"
                
                html += f"""
        <button class="collapsible">
            <span>{i+1}. {self._get_vuln_type_chinese(vuln_type)} - {self._get_risk_chinese(risk)}</span>
            <span>{vuln.get('url', '')}</span>
        </button>
        <div class="content">
            <table class="vuln-table">
                <tr>
                    <th>漏洞类型</th>
                    <td>{self._get_vuln_type_chinese(vuln_type)}</td>
                </tr>
                <tr>
                    <th>风险等级</th>
                    <td class="risk-{risk}">{self._get_risk_chinese(risk)}</td>
                </tr>
                <tr>
                    <th>URL</th>
                    <td>{vuln.get('url', 'N/A')}</td>
                </tr>
                <tr>
                    <th>HTTP方法</th>
                    <td>{vuln.get('method', 'GET')}</td>
                </tr>
                <tr>
                    <th>影响参数</th>
                    <td>{vuln.get('param', 'N/A')}</td>
                </tr>
                <tr>
                    <th>注入Payload</th>
                    <td>{vuln.get('payload', 'N/A')}</td>
                </tr>
                <tr>
                    <th>证据</th>
                    <td>{vuln.get('evidence', 'N/A')}</td>
                </tr>
            </table>
            
            <h4>漏洞修复建议</h4>
            <div class="recommendations">
                {self._get_vuln_recommendations(vuln_type)}
            </div>
        </div>
"""
        else:
            html += """
        <div class="summary" style="border-left: 5px solid #5cb85c;">
            <h2>恭喜！未发现明显安全漏洞</h2>
            <p>虽然本次扫描未发现明显的安全漏洞，但安全是一个持续的过程。建议定期扫描和审计您的网站，以确保安全性。</p>
        </div>
"""
        
        # HTML页脚
        html += """
        <div class="recommendations">
            <h2>通用安全建议</h2>
            <ul>
                <li>始终保持Web应用框架和依赖库的最新版本</li>
                <li>实施内容安全策略(CSP)以减少XSS攻击的风险</li>
                <li>使用HTTPS确保传输安全</li>
                <li>正确配置Web服务器，删除不必要的服务和默认页面</li>
                <li>实施暴力破解防护措施，如账户锁定和CAPTCHA</li>
                <li>定期进行安全审计和漏洞扫描</li>
                <li>制定安全事件响应计划</li>
            </ul>
        </div>

        <div class="footer">
            <p>WebShield 安全扫描报告 &copy; 2023</p>
            <p>本报告仅供参考，不能替代专业的安全评估</p>
        </div>
    </div>

    <script>
    var coll = document.getElementsByClassName("collapsible");
    var i;

    for (i = 0; i < coll.length; i++) {
        coll[i].addEventListener("click", function() {
            this.classList.toggle("active");
            var content = this.nextElementSibling;
            if (content.style.maxHeight) {
                content.style.maxHeight = null;
            } else {
                content.style.maxHeight = content.scrollHeight + "px";
            }
        });
    }
    </script>
</body>
</html>
"""
        
        return html
    
    def _get_risk_level_chinese(self, level):
        """将风险等级翻译为中文"""
        risk_map = {
            'Critical': '严重风险',
            'High': '高风险',
            'Medium': '中等风险',
            'Low': '低风险',
            'Safe': '安全'
        }
        return risk_map.get(level, level)
    
    def _get_risk_chinese(self, risk):
        """将风险等级翻译为中文"""
        risk_map = {
            'high': '高风险',
            'medium': '中等风险',
            'low': '低风险'
        }
        return risk_map.get(risk, risk)
    
    def _get_vuln_type_chinese(self, vuln_type):
        """将漏洞类型翻译为中文"""
        type_map = {
            'sql_injection': 'SQL注入漏洞',
            'xss': 'XSS跨站脚本漏洞',
            'csrf': 'CSRF跨站请求伪造漏洞',
            'other': '其他漏洞'
        }
        return type_map.get(vuln_type, vuln_type)
    
    def _get_vuln_recommendations(self, vuln_type):
        """获取特定漏洞类型的修复建议"""
        recommendations = {
            'sql_injection': """
                <ul>
                    <li>使用参数化查询（预处理语句）来替代直接拼接SQL语句</li>
                    <li>使用ORM框架，如SQLAlchemy、Hibernate等</li>
                    <li>对所有用户输入进行严格的验证和过滤</li>
                    <li>应用程序使用最小权限数据库账户</li>
                    <li>启用预处理语句的强制参数化</li>
                    <li>避免在错误消息中透露数据库信息</li>
                </ul>
            """,
            'xss': """
                <ul>
                    <li>对所有用户输入和输出进行HTML转义</li>
                    <li>实施内容安全策略(CSP)</li>
                    <li>使用现代框架的内置XSS保护功能</li>
                    <li>使用HttpOnly标志保护Cookies</li>
                    <li>对HTML属性和JavaScript内容使用适当的上下文转义</li>
                    <li>过滤不必要的HTML标签和属性</li>
                </ul>
            """,
            'csrf': """
                <ul>
                    <li>在所有表单中使用CSRF令牌</li>
                    <li>实施同源检查(Origin/Referer)</li>
                    <li>对敏感操作使用用户交互确认</li>
                    <li>使用自定义请求头(如X-Requested-With)</li>
                    <li>设置SameSite Cookie属性</li>
                    <li>对关键操作实施重新认证</li>
                </ul>
            """,
            'other': """
                <ul>
                    <li>保持应用程序和依赖项的最新安全补丁</li>
                    <li>进行定期安全审计和代码审查</li>
                    <li>遵循安全开发生命周期(SDLC)最佳实践</li>
                    <li>实施安全监控和日志记录</li>
                </ul>
            """
        }
        
        return recommendations.get(vuln_type, recommendations['other']) 