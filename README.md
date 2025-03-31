# WebShield - Web应用漏洞扫描器

WebShield是一款功能强大的Web应用漏洞扫描工具，可以帮助开发者和安全测试人员发现并修复常见的Web安全漏洞，如SQL注入、XSS和CSRF等。

## 功能特点

- **自动网站爬虫**：自动发现Web应用的入口点和表单
- **多种漏洞检测**：检测SQL注入、XSS跨站脚本和CSRF跨站请求伪造等常见漏洞
- **风险评估系统**：对发现的漏洞进行风险评分和分级
- **详细安全报告**：生成全面的安全报告，包括漏洞详情和修复建议
- **用户友好界面**：提供简洁直观的Web界面，方便操作和查看结果

## 技术架构

- 后端：Python + Flask
- 前端：HTML/CSS/JavaScript + Bootstrap
- 网络库：Requests
- HTML解析：Beautiful Soup
- 无数据库设计，使用文件系统存储扫描结果

## 安装和部署

### 环境要求

- Python 3.8+
- 相关Python依赖包

### 安装步骤

1. 克隆项目仓库

```bash
git clone https://github.com/your-username/webshield.git
cd webshield
```

2. 创建虚拟环境（可选但推荐）

```bash
python -m venv webshield
source webshield/bin/activate  # Linux/Mac
```

3. 安装依赖

```bash
pip install -r requirements.txt
```

4. 运行应用

```bash
python run.py
```

5. 在浏览器中访问应用

```
http://127.0.0.1:5000
```

## 使用说明

1. 在主页点击"开始扫描"按钮
2. 输入目标网站URL（必须以http://或https://开头）
3. 选择扫描深度和要检测的漏洞类型
4. 点击"开始扫描"按钮开始扫描
5. 等待扫描完成，查看详细的安全报告
6. 根据报告中的建议修复发现的漏洞

## 使用漏洞测试应用进行测试

项目包含了一个专用的漏洞测试应用，可用于验证WebShield的扫描和检测能力。

### 测试应用功能

测试应用故意包含多种常见漏洞，包括：

- **SQL注入漏洞**：用户查询、产品搜索和登录页面
- **XSS跨站脚本漏洞**：留言板(存储型)和搜索页面(反射型)
- **CSRF跨站请求伪造漏洞**：个人资料修改页面

### 安装和运行测试应用

1. 进入漏洞测试应用目录
```bash
cd vulnerable_testapp
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

3. 启动测试应用
```bash
python app.py
```

4. 测试应用将在 http://localhost:5001 运行

### 使用WebShield扫描测试应用

1. 确保测试应用正在运行
2. 打开WebShield（在另一个终端中运行`python run.py`）
3. 在WebShield扫描器中输入URL：`http://localhost:5001`
4. 选择要扫描的漏洞类型（建议全选）
5. 设置扫描深度为2或更高
6. 点击"开始扫描"按钮
7. 扫描完成后，检查WebShield是否成功识别测试应用中的所有漏洞

### 安全提示

⚠️ **警告**：漏洞测试应用故意包含安全漏洞，仅用于测试目的！
- 请勿在生产环境中部署
- 仅在本地网络或受控环境中运行
- 不要在其中存储真实数据

## 作者

北京邮电大学22级学生

## 许可证

本项目采用MIT许可证。详情请参阅LICENSE文件。 