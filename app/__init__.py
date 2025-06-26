from flask import Flask
import os
from dotenv import load_dotenv

def create_app():
    # 加载环境变量
    load_dotenv()
    
    app = Flask(__name__, instance_relative_config=True)
    app.secret_key = os.getenv('FLASK_SECRET_KEY', 'fallback_secret_key')

    # 确保 instance 文件夹存在
    os.makedirs(app.instance_path, exist_ok=True)

    # 初始化数据库
    from .models import init_database
    init_database()

    # 注册蓝图
    from .routes import bp
    app.register_blueprint(bp)

    return app