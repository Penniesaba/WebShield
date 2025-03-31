#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WebShield - Web应用漏洞扫描器
Flask应用初始化
"""

import os
import json
from datetime import datetime
from flask import Flask

def create_app():
    """创建并配置Flask应用实例"""
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY='webshield_secret_key',
        # 扫描结果存储路径
        SCAN_RESULTS_DIR=os.path.join(app.instance_path, 'scan_results'),
        # 报告存储路径
        REPORTS_DIR=os.path.join(app.instance_path, 'reports')
    )
    
    # 确保存储目录存在
    try:
        os.makedirs(app.config['SCAN_RESULTS_DIR'])
        os.makedirs(app.config['REPORTS_DIR'])
    except OSError:
        pass
    
    # 注册路由
    from app import routes
    routes.init_app(app)
    
    # 在应用创建时直接记录启动信息，而不使用before_first_request
    app.logger.info('WebShield 应用启动成功')
    
    return app 