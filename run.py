#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
WebShield - Web应用漏洞扫描器
主程序入口
"""

from app import create_app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True) 