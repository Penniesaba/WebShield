#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WebShield - Web应用漏洞扫描器
Flask路由定义
"""

import os
import json
import uuid
from datetime import datetime
from flask import render_template, request, jsonify, current_app, redirect, url_for, abort, send_from_directory

# 导入扫描器相关模块
from app.scanner.crawler import WebCrawler
from app.scanner.report import VulnerabilityReportGenerator
from app.scanner.detector.sql_injection import SQLInjectionDetector
from app.scanner.detector.xss import XSSDetector
from app.scanner.detector.csrf import CSRFDetector

def init_app(app):
    """初始化路由"""
    
    @app.route('/')
    def index():
        """首页 - 扫描器主界面"""
        return render_template('index.html')
    
    @app.route('/scan', methods=['GET', 'POST'])
    def scan():
        """执行扫描操作"""
        if request.method == 'POST':
            target_url = request.form.get('target_url')
            scan_depth = int(request.form.get('scan_depth', 2))
            scan_options = {
                'sql_injection': 'sql_injection' in request.form,
                'xss': 'xss' in request.form,
                'csrf': 'csrf' in request.form
            }
            
            # 验证URL
            if not target_url or not target_url.startswith(('http://', 'https://')):
                return jsonify({'error': '请输入有效的URL，必须以http://或https://开头'}), 400
            
            # 生成唯一的扫描ID
            scan_id = str(uuid.uuid4())
            
            # 创建任务状态文件
            scan_info = {
                'id': scan_id,
                'target_url': target_url,
                'scan_depth': scan_depth,
                'scan_options': scan_options,
                'status': 'running',
                'start_time': datetime.now().isoformat(),
                'end_time': None,
                'progress': 0
            }
            
            # 保存扫描状态到文件
            result_path = os.path.join(current_app.config['SCAN_RESULTS_DIR'], f'{scan_id}.json')
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(scan_info, f, ensure_ascii=False, indent=2)
            
            # 启动扫描（在实际应用中应该使用异步任务）
            try:
                # 初始化爬虫
                crawler = WebCrawler(target_url, depth=scan_depth)
                urls = crawler.crawl()
                
                # 进行各项漏洞检测
                vulnerabilities = []
                
                if scan_options['sql_injection']:
                    sql_detector = SQLInjectionDetector()
                    sql_results = sql_detector.scan_urls(urls)
                    vulnerabilities.extend(sql_results)
                
                if scan_options['xss']:
                    xss_detector = XSSDetector()
                    xss_results = xss_detector.scan_urls(urls)
                    vulnerabilities.extend(xss_results)
                
                if scan_options['csrf']:
                    csrf_detector = CSRFDetector()
                    csrf_results = csrf_detector.scan_urls(urls)
                    vulnerabilities.extend(csrf_results)
                
                # 生成报告
                report_generator = VulnerabilityReportGenerator(scan_id, target_url, vulnerabilities)
                report_path = report_generator.generate_report()
                
                # 计算风险评分和分类
                risk_score = report_generator._calculate_risk_score()
                
                # 更新扫描状态
                scan_info.update({
                    'status': 'completed',
                    'end_time': datetime.now().isoformat(),
                    'progress': 100,
                    'urls_discovered': len(urls),
                    'vulnerabilities_found': len(vulnerabilities),
                    'vulnerabilities': vulnerabilities,
                    'report_path': report_path,
                    'score': risk_score['score'],
                    'risk_level': risk_score['level'],
                    'total_vulnerabilities': risk_score['total_vulnerabilities'],
                    'vulnerability_counts': risk_score['vulnerability_counts'],
                    'risk_counts': risk_score['risk_counts']
                })
                
                # 保存最终结果
                with open(result_path, 'w', encoding='utf-8') as f:
                    json.dump(scan_info, f, ensure_ascii=False, indent=2)
                
                return redirect(url_for('scan_result', scan_id=scan_id))
                
            except Exception as e:
                current_app.logger.error(f"扫描过程中出错: {str(e)}")
                # 更新为失败状态
                scan_info.update({
                    'status': 'failed',
                    'end_time': datetime.now().isoformat(),
                    'error': str(e)
                })
                with open(result_path, 'w', encoding='utf-8') as f:
                    json.dump(scan_info, f, ensure_ascii=False, indent=2)
                
                return jsonify({'error': f"扫描失败: {str(e)}"}), 500
        
        # GET请求返回扫描页面
        return render_template('scan.html')
    
    @app.route('/scan_result/<scan_id>')
    def scan_result(scan_id):
        """显示扫描结果"""
        result_path = os.path.join(current_app.config['SCAN_RESULTS_DIR'], f'{scan_id}.json')
        
        if not os.path.exists(result_path):
            abort(404)
        
        with open(result_path, 'r', encoding='utf-8') as f:
            scan_info = json.load(f)
        
        # 确保所有必要的字段存在，防止模板渲染时出错
        if scan_info.get('status') == 'completed':
            # 风险评分相关字段
            if 'risk_counts' not in scan_info:
                scan_info['risk_counts'] = {'high': 0, 'medium': 0, 'low': 0}
            elif not isinstance(scan_info['risk_counts'], dict):
                scan_info['risk_counts'] = {'high': 0, 'medium': 0, 'low': 0}
            else:
                # 确保risk_counts中包含所有必要的子字段
                for key in ['high', 'medium', 'low']:
                    if key not in scan_info['risk_counts']:
                        scan_info['risk_counts'][key] = 0
            
            # 漏洞计数相关字段
            if 'vulnerability_counts' not in scan_info:
                scan_info['vulnerability_counts'] = {'sql_injection': 0, 'xss': 0, 'csrf': 0, 'other': 0}
            elif not isinstance(scan_info['vulnerability_counts'], dict):
                scan_info['vulnerability_counts'] = {'sql_injection': 0, 'xss': 0, 'csrf': 0, 'other': 0}
            else:
                # 确保vulnerability_counts中包含所有必要的子字段
                for key in ['sql_injection', 'xss', 'csrf', 'other']:
                    if key not in scan_info['vulnerability_counts']:
                        scan_info['vulnerability_counts'][key] = 0
            
            # 其他必要字段
            if 'total_vulnerabilities' not in scan_info:
                vulns = scan_info.get('vulnerabilities', [])
                scan_info['total_vulnerabilities'] = len(vulns) if isinstance(vulns, list) else 0
            
            if 'score' not in scan_info:
                scan_info['score'] = 0
                
            if 'risk_level' not in scan_info:
                scan_info['risk_level'] = 'Safe'
            
            if 'urls_discovered' not in scan_info:
                scan_info['urls_discovered'] = 0
        
        return render_template('scan_result.html', scan_info=scan_info)
    
    @app.route('/reports/<scan_id>')
    def download_report(scan_id):
        """下载报告文件"""
        return send_from_directory(
            current_app.config['REPORTS_DIR'],
            f"{scan_id}.html",
            as_attachment=True,
            download_name=f"webshield_report_{scan_id[:8]}.html"
        )
    
    @app.route('/api/scan_status/<scan_id>')
    def scan_status(scan_id):
        """获取扫描状态的API"""
        result_path = os.path.join(current_app.config['SCAN_RESULTS_DIR'], f'{scan_id}.json')
        
        if not os.path.exists(result_path):
            return jsonify({'error': '扫描ID无效'}), 404
        
        with open(result_path, 'r', encoding='utf-8') as f:
            scan_info = json.load(f)
        
        return jsonify(scan_info)
    
    @app.route('/history')
    def scan_history():
        """扫描历史记录页面"""
        scan_results = []
        for filename in os.listdir(current_app.config['SCAN_RESULTS_DIR']):
            if filename.endswith('.json'):
                try:
                    with open(os.path.join(current_app.config['SCAN_RESULTS_DIR'], filename), 'r', encoding='utf-8') as f:
                        scan_info = json.load(f)
                        scan_results.append(scan_info)
                except Exception as e:
                    current_app.logger.error(f"读取扫描历史记录出错: {str(e)}")
        
        # 按开始时间排序，最新的排在前面
        scan_results = sorted(scan_results, key=lambda x: x.get('start_time', ''), reverse=True)
        
        return render_template('history.html', scan_results=scan_results) 