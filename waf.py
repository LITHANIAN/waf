from flask import Flask, request, abort, redirect
from logging.handlers import RotatingFileHandler
import re
from datetime import datetime
import logging
from werkzeug.datastructures import MultiDict
import os

# 初始化Flask应用
app = Flask(__name__)

# 配置日志系统
def setup_logger():
    logger = logging.getLogger('waf_logger')
    logger.setLevel(logging.INFO)
    
    # 确保日志目录存在
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    handler = RotatingFileHandler(
        'logs/waf.log',  # 将日志文件放入logs目录
        maxBytes=1024 * 1024,  # 1MB
        backupCount=5,        # 保留5个历史文件
        encoding='utf-8'
    )
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logger()

# 漏洞检测规则引擎
class WAFRules:
    @staticmethod
    def detect_sql_injection(payload):
        """检测SQL注入（进一步优化）"""
        patterns = [
            r"(?i)\b(?:union\s+select|select\s+(?:.*?\s+)?from|--|%2d|%252d)\b",  # 联合查询和数据泄露
            r"(?i)\b(?:1=1|1=0|--|%00)\b",  # 布尔盲注
            r"(?i)\b(?:sleep\(|benchmark\s*\(|ascii\(|substr\(|conv\()",  # 时间盲注和错误注入
            r"(?i)\b(?:union.*all\s+select)",  # 绕过空格过滤
        ]
        return any(re.search(p, str(payload)) for p in patterns)

    @staticmethod
    def detect_xss(payload):
        """检测XSS（进一步优化）"""
        patterns = [
            r'(?i)<script[^>]*>.*?</script>',  # script标签
            r'(?i)javascript\s*:',  # javascript伪协议（添加空格处理）
            r'(?i)on\w+\s*=',  # 事件处理器
            r'(?i)\b(alert|prompt|confirm)\s*\(',  # 弹窗函数（添加括号处理）
            r'(?i)src[\s:=]+javascript:',  # src属性注入
            r'(?i)\b(document\.cookie|location\.href)\b'  # 防御DOM-based XSS
        ]
        return any(re.search(p, str(payload)) for p in patterns)

    @staticmethod
    def detect_command_injection(payload):
        """检测命令注入（进一步优化）"""
        patterns = [
            r"(?i)(?:;|\||&|`|\$\(|\$\{)",  # 命令分隔符
            r"(?i)(?:rm\s+-rf|cat\s+/etc/passwd|wget|curl|nc\s+|telnet\s+)",  # 危险命令
            r"(?i)(?:\.\./|\.\.\\|%0a|%0d)",  # 路径遍历
            r"(?i)(?:eval\s*\(|system\s*\(|exec\s*\(|passthru\s*\()",  # 执行函数
            r"(?i)(?:\|\||&&|;|\$\(|\$\{|\`|\|$)",  # 管道符和逻辑运算符
        ]
        return any(re.search(p, str(payload)) for p in patterns)

    @staticmethod
    def detect_code_injection(payload):
        """检测代码注入（PHP示例）"""
        patterns = [
            r'(?i)<\?php|\%3C\?php',  # PHP标签
            r'(?i)\beval\s*\(',  # eval函数
            r'(?i)\bassert\s*\(',  # assert函数
            r'(?i)\b(include|require)(_once)?\s*\(',  # 文件包含
        ]
        return any(re.search(p, str(payload)) for p in patterns)

# 请求处理核心逻辑
@app.before_request
def waf_check():
    # 仅排除对根路径和图标路径的检查
    if request.path in ['/', '/favicon.ico']:
        return
    
    # 构建请求指纹
    payload = {
        'method': request.method,
        'path': request.path,
        'ip': request.remote_addr,
        'headers': dict(request.headers),
        'args': dict(request.args),  # URL参数
        'form': dict(request.form),  # POST表单参数
        'cookies': dict(request.cookies)
    }

    # 检查请求参数
    locations = [
        ('URL参数', payload['args']),
        ('Body参数', payload['form']),
        ('Header', payload['headers']),
        ('Cookie', payload['cookies'])
    ]

    for location_name, params in locations:
        if not isinstance(params, MultiDict):  # 处理特殊类型
            params = MultiDict(params)
        
        for param_name, param_value in params.items():
            if any([
                WAFRules.detect_sql_injection(param_value),
                WAFRules.detect_xss(param_value),
                WAFRules.detect_command_injection(param_value),
                WAFRules.detect_code_injection(param_value)
            ]):
                log_entry = f"""
=== 拦截日志 ===
时间: {datetime.now()}
源IP: {payload['ip']}
请求路径: {payload['path']}
请求方法: {payload['method']}
危险位置: {location_name}.{param_name}
危险值: {param_value}
"""
                logger.warning(log_entry.strip())
                print(log_entry.strip())  # 同时打印到控制台，便于调试
                abort(403, description="恶意请求已被拦截")

# 根路径路由
@app.route('/')
def index():
    # 直接返回测试页面内容
    return test_waf()

# 测试路由（支持GET和POST方法）
@app.route('/test', methods=['GET', 'POST'])
def test_waf():
    # 处理POST请求（XSS测试）
    if request.method == 'POST':
        q = request.form.get('q', '')
        # 简单处理POST请求，实际环境中可能需要根据业务逻辑处理
        return f"接收到POST参数: q={q}"
    
    # 默认返回测试页面
    return """
    <h2>WAF测试端点</h2>
    
    <!-- SQL注入测试 -->
    <form action="/test" method="GET">
        <input type="text" name="id" value="1' UNION SELECT null,password,null FROM users--">
        <button>SQL注入测试</button>
    </form>

    <!-- XSS测试 -->
    <form action="/test" method="POST">
        <input type="text" name="q" value="<script>alert(1)</script>">
        <button>XSS测试</button>
    </form>

    <!-- 命令注入测试 -->
    <form action="/test" method="GET">
        <input type="text" name="cmd" value="cat /etc/passwd">
        <button>命令注入测试</button>
    </form>
    """

# 错误处理
@app.errorhandler(403)
def handle_block(e):
    return f"""
    <h1>请求被拦截</h1>
    <p>{e.description}</p>
    <a href="/">返回首页</a>
    """, 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)