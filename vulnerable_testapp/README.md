# WebShield 漏洞测试应用

这是一个专为WebShield Web应用漏洞扫描器测试而创建的测试应用。该应用故意包含多种常见Web安全漏洞，用于评估扫描器的检测能力。

## 包含的漏洞类型

1. **SQL注入漏洞**
   - 用户查询页面 (`/user`)
   - 产品搜索页面 (`/products`)
   - 登录页面 (`/login`)

2. **跨站脚本(XSS)漏洞**
   - 存储型XSS: 留言板页面 (`/messages`)
   - 反射型XSS: 搜索页面 (`/search`)

3. **跨站请求伪造(CSRF)漏洞**
   - 个人资料修改页面 (`/profile`)

## 安装与运行

### 前提条件

- Python 3.8+

### 安装步骤

1. 克隆此仓库或下载源代码
2. 进入项目目录
3. 创建虚拟环境（推荐）

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
venv\Scripts\activate  # Windows
```

4. 安装依赖

```bash
pip install -r requirements.txt
```

5. 运行应用

```bash
python app.py
```

6. 访问网站

浏览器打开 http://localhost:5001

## 使用说明

1. 启动此漏洞测试应用
2. 启动WebShield扫描器
3. 在扫描器中输入URL: `http://localhost:5001`
4. 选择要测试的漏洞类型（推荐全选）
5. 设置扫描深度（建议至少为2）
6. 开始扫描并查看结果

## 安全警告

**⚠️ 警告:** 此应用程序故意包含安全漏洞，仅用于测试目的！

- 请勿在生产环境中部署
- 不要在公共网络上运行
- 不要在其中存储敏感信息
- 仅在受控环境中使用

## 漏洞利用测试

各页面中包含了漏洞提示，说明了如何利用这些漏洞。您可以手动测试这些漏洞，然后使用WebShield扫描器验证是否能检测到它们。 