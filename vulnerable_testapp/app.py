#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
漏洞测试应用 - 用于测试WebShield扫描器
包含SQL注入、XSS和CSRF漏洞
"""

import os
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, g, session

app = Flask(__name__)
app.secret_key = 'vulnerable_testapp_secret_key'
app.config['DATABASE'] = os.path.join(app.instance_path, 'test.db')

# 确保instance目录存在
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# 数据库操作
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    
    # 创建用户表
    db.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    
    # 创建留言表
    db.execute('''
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    
    # 创建产品表
    db.execute('''
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL
    )
    ''')
    
    # 添加一些测试数据
    db.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')")
    db.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (2, 'user', 'password')")
    
    db.execute("INSERT OR IGNORE INTO messages (id, user_id, content) VALUES (1, 1, '这是一条管理员留言')")
    db.execute("INSERT OR IGNORE INTO messages (id, user_id, content) VALUES (2, 2, '这是一条普通用户留言')")
    
    db.execute("INSERT OR IGNORE INTO products (id, name, description, price) VALUES (1, '测试产品1', '这是产品1的描述', 99.99)")
    db.execute("INSERT OR IGNORE INTO products (id, name, description, price) VALUES (2, '测试产品2', '这是产品2的描述', 199.99)")
    
    db.commit()

# 初始化数据库
with app.app_context():
    init_db()

# 首页
@app.route('/')
def index():
    return render_template('index.html')

# SQL注入漏洞示例 - 用户查询
@app.route('/user', methods=['GET'])
def user_search():
    username = request.args.get('username', '')
    result = None
    
    if username:
        # SQL注入漏洞 - 直接拼接参数
        db = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}'"
        
        try:
            result = db.execute(query).fetchone()
        except Exception as e:
            return f"查询出错: {str(e)}"
    
    return render_template('user_search.html', username=username, result=result)

# SQL注入漏洞示例 - 产品搜索
@app.route('/products', methods=['GET'])
def product_search():
    search = request.args.get('search', '')
    results = []
    
    if search:
        # SQL注入漏洞 - 直接拼接参数
        db = get_db()
        query = f"SELECT * FROM products WHERE name LIKE '%{search}%' OR description LIKE '%{search}%'"
        
        try:
            results = db.execute(query).fetchall()
        except Exception as e:
            return f"查询出错: {str(e)}"
    
    return render_template('product_search.html', search=search, results=results)

# XSS漏洞示例 - 留言板
@app.route('/messages', methods=['GET', 'POST'])
def messages():
    db = get_db()
    
    if request.method == 'POST':
        content = request.form.get('content', '')
        
        if content:
            # 存储型XSS漏洞 - 不过滤用户输入
            db.execute("INSERT INTO messages (user_id, content) VALUES (?, ?)", (1, content))
            db.commit()
            return redirect(url_for('messages'))
    
    # 获取所有留言
    all_messages = db.execute("SELECT * FROM messages ORDER BY created_at DESC").fetchall()
    
    return render_template('messages.html', messages=all_messages)

# XSS漏洞示例 - 反射型
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # 反射型XSS漏洞 - 直接输出用户输入
    return render_template('search.html', query=query)

# CSRF漏洞示例
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        new_password = request.form.get('password', '')
        
        if new_password:
            # CSRF漏洞 - 无Token验证
            db = get_db()
            db.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, 1))
            db.commit()
            return "密码已更新!"
    
    return render_template('profile.html')

# 登录页面 - 不安全的实现
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        db = get_db()
        
        # SQL注入漏洞 - 直接拼接参数
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = db.execute(query).fetchone()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        else:
            error = '无效的用户名或密码'
    
    return render_template('login.html', error=error)

# 注销
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001) 