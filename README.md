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

## 作者

北京邮电大学22级学生

## 许可证

本项目采用MIT许可证。详情请参阅LICENSE文件。 