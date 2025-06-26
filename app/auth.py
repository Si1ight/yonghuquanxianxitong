from functools import wraps
from flask import jsonify, session, redirect, current_app

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'status': 'error', 'message': '未登录'}), 401
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                return jsonify({'status': 'error', 'message': '未登录'}), 401
            if session['user']['role'] != required_role:
                return jsonify({'status': 'error', 'message': f'需要{required_role}权限'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 定义角色常量
ROLE_ADMIN = 'admin'
ROLE_DESIGNER = 'designer'
ROLE_USER = 'user'