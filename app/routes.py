from flask import Blueprint, request, jsonify, session, redirect, render_template
from .models import Database
from .auth import login_required, role_required, ROLE_ADMIN, ROLE_DESIGNER, ROLE_USER
import hashlib
import requests  

bp = Blueprint('main', __name__)

# DeepSeek API 配置
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
DEEPSEEK_API_KEY = "sk-9a8d1ff0081d4ed1b9cfe18b87c63772"  

@bp.route('/')
def index():
    if 'user' in session:
        return redirect('/main')
    return render_template('login.html')

@bp.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return jsonify({'status': 'error', 'message': '用户名和密码不能为空'}), 400
    
    db = Database()
    user = db.get_user_by_username(username)
    
    if user and hashlib.sha256(password.encode()).hexdigest() == user['password']:
        session['user'] = {
            'user_id': user['user_id'],
            'username': user['username'],
            'role': user['role']
        }
        return jsonify({'status': 'success', 'redirect': '/main'})
    else:
        return jsonify({'status': 'error', 'message': '用户名或密码错误'}), 401

@bp.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

@bp.route('/main')
@login_required
def main():
    return render_template('main.html', role=session['user']['role'])

# 用户管理路由 - 仅管理员可见
@bp.route('/user_management')
@login_required
@role_required(ROLE_ADMIN)
def user_management():
    return render_template('user_management.html')

# 数据管理路由 - 不同角色均可访问，但权限不同
@bp.route('/data_management')
@login_required
def data_management():
    return render_template('data_management.html', role=session['user']['role'])

@bp.route('/api/ai/ask', methods=['POST'])
@login_required
def ai_ask():
    # 保持原有逻辑不变
    try:
        data = request.json
        question = data.get('question', '').strip()
        context = data.get('context', '')
        
        if not question:
            return jsonify({'status': 'error', 'message': '问题不能为空'}), 400
        
        # 构建DeepSeek API请求
        headers = {
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": "deepseek-chat",
            "messages": [
                {
                    "role": "system",
                    "content": """你是一个用户权限系统的AI助手。请用中文回答用户问题，回答要简洁专业。下面是此程序的详细信息：
                    ### 程序概述
这是一个基于Flask框架开发的用户权限管理系统，具备用户登录、登出、用户管理、数据管理等功能，同时集成了DeepSeek AI API以提供智能问答服务，程序的编写者为SLT

### 主要功能模块
1. **用户认证**：支持用户登录和登出，使用哈希算法对密码进行加密存储。
2. **权限管理**：定义了三种角色（管理员、设计师、普通用户），不同角色具有不同的操作权限。
3. **用户管理**：仅管理员可以进行用户的增删改查操作。
4. **数据管理**：不同角色对数据的操作权限不同，如普通用户只能查看数据，管理员和设计师可以进行增删改查操作。
5. **智能问答**：通过调用DeepSeek AI API，为用户提供与用户权限系统相关的问题解答。

### 主要文件及功能
1. **routes.py**：定义了应用的路由和视图函数，处理用户请求和业务逻辑。
2. **models.py**：封装了数据库操作，包括用户和数据的增删改查。
3. **__init__.py**：创建Flask应用实例，加载环境变量，初始化数据库，并注册蓝图。
4. **auth.py**：定义了登录和角色验证的装饰器，用于保护需要认证的路由。

### 数据库设计
- **users表**：存储用户信息，包括用户ID、用户名、密码、角色和创建时间。
- **data表**：存储数据信息，包括数据ID、数据名称、数据类型、内容、创建者ID、创建时间和更新时间。

### 代码片段示例
以下是部分关键代码片段：
@bp.route('/api/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
@role_required(ROLE_ADMIN)
def users_api():
    # 保持原有逻辑不变
    db = Database()
    
    if request.method == 'GET':
        condition = request.args.get('q', '')
        if condition.isdigit():  # 如果传入的是数字，认为是用户 ID，进行精确匹配
            user = db.get_user_by_id(int(condition))
            if user:
                return jsonify({
                    'status': 'success',
                    'data': [{
                        'user_id': user['user_id'],
                        'username': user['username'],
                        'role': user['role'],
                        'create_time': user['create_time']
                    }]
                })
            return jsonify({'status': 'success', 'data': []})
        else:  # 否则进行模糊搜索
            users = db.get_user_list(condition)
            return jsonify({
                'status': 'success',
                'data': [{
                    'user_id': u[0],
                    'username': u[1],
                    'role': u[2],
                    'create_time': u[3]
                } for u in users]
            })
    
    elif request.method == 'POST':
        data = request.json
        if not all(key in data for key in ['username', 'password', 'role']):
            return jsonify({'status': 'error', 'message': '缺少必要字段'}), 400
            
        user_id = db.add_user(data)
        if user_id:
            return jsonify({
                'status': 'success',
                'data': {'user_id': user_id}
            })
        return jsonify({'status': 'error', 'message': '创建用户失败'}), 500
    
    elif request.method == 'PUT':
        data = request.json
        if not all(key in data for key in ['user_id', 'username', 'role']):
            return jsonify({'status': 'error', 'message': '缺少必要字段'}), 400
            
        if db.update_user(data) is not None:
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': '更新用户失败'}), 500
    
    elif request.method == 'DELETE':
        user_id = request.json.get('user_id')
        if not user_id:
            return jsonify({'status': 'error', 'message': '缺少用户 ID'}), 400
            
        if db.delete_user(user_id) is not None:
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': '删除用户失败'}), 500

@bp.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
@role_required(ROLE_ADMIN)
def get_single_user(user_id):
    # 保持原有逻辑不变
    db = Database()
    user = db.get_user_by_id(user_id)
    if user:
        return jsonify({
            'status': 'success',
            'data': {
                'user_id': user['user_id'],
                'username': user['username'],
                'role': user['role'],
                'create_time': user['create_time']
            }
        })
    return jsonify({'status': 'error', 'message': '用户不存在'}), 404

# 数据API路由 - 根据角色控制权限
@bp.route('/api/data', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def data_api():
    db = Database()
    user_id = session['user']['user_id']
    user_role = session['user']['role']
    
    if request.method == 'GET':
        condition = request.args.get('q', '')
        # 所有角色都可以查看所有数据，不再传递 user_id
        data = db.get_data_list(condition)
        
        # 为每个数据项添加权限标志
        result = []
        for d in data:
            data_item = {
                'data_id': d[0],
                'data_name': d[1],
                'data_type': d[2],
                'content': d[3],
                'creator': d[4],  # 假设d[4]是creator的用户名
                'create_time': d[5],
                'update_time': d[6],
                # 权限控制
                'can_edit': user_role == ROLE_ADMIN or user_role == ROLE_DESIGNER,
                'can_delete': user_role == ROLE_ADMIN or user_role == ROLE_DESIGNER,
            }
            result.append(data_item)
        
        return jsonify({
            'status': 'success',
            'data': result,
            'total': len(result)  # 暂时使用这个，实际应该从数据库获取总数
        })
    
    elif request.method in ['POST', 'PUT']:  # 合并POST和PUT的处理逻辑
        data = request.json
        # 强制校验必要字段，避免空值导致的创建失败
        required_fields = ['data_name', 'data_type', 'content']
        if not all(key in data for key in required_fields):
            missing = ', '.join([f"'{k}'" for k in required_fields if k not in data])
            return jsonify({'status': 'error', 'message': f'缺少必要字段: {missing}'}), 400
            
        # 权限控制：use不能添加数据，designer和admin可以添加
        if user_role == ROLE_USER :
            return jsonify({'status': 'error', 'message': '无权限操作'}), 403
        
        if request.method == 'POST':
            # 添加新数据
            new_data = db.add_data(data, user_id)
            if new_data:
                return jsonify({
                    'status': 'success',
                    'data': {
                        'data_id': new_data[0],
                        'data_name': new_data[1],
                        'data_type': new_data[2],
                        'content': new_data[3],
                        'creator': new_data[4],
                        'create_time': new_data[5],
                        'update_time': new_data[6]
                    }
                })
        else:  # PUT请求
            data_id = data.get('data_id')
            if not data_id:
                return jsonify({'status': 'error', 'message': '缺少数据ID'}), 400
                
            db_data = db.get_data_by_id(data_id)
            if not db_data:
                return jsonify({'status': 'error', 'message': '数据不存在'}), 404
                
            
            if user_role == ROLE_USER:
                return jsonify({'status': 'error', 'message': '无权限编辑数据'}), 403          
            
            updated_data = db.update_data(data)
            if updated_data:
                return jsonify({
                    'status': 'success',
                    'data': {
                        'data_id': updated_data[0],
                        'data_name': updated_data[1],
                        'data_type': updated_data[2],
                        'content': updated_data[3],
                        'creator': updated_data[4],
                        'create_time': updated_data[5],
                        'update_time': updated_data[6]
                    }
                })
        
            return jsonify({'status': 'error', 'message': '保存数据失败，请检查数据库连接'}), 500
    
    elif request.method == 'DELETE':
        # 修改为从请求体中获取数据
        data = request.get_json()
        if not data or 'data_id' not in data:
            return jsonify({'status': 'error', 'message': '缺少数据ID'}), 400
            
        data_id = data['data_id']
        db_data = db.get_data_by_id(data_id)
        if not db_data:
            return jsonify({'status': 'error', 'message': '数据不存在'}), 404
            
        # 权限校验 - 确保用户有权限删除数据
        creator_id = db_data[4]  # 假设db_data[4]是creator_id
        if user_role == ROLE_USER:
            return jsonify({'status': 'error', 'message': '无权限删除数据'}), 403
        
            
        try:
            delete_result = db.delete_data(data_id)
            if delete_result is not None:
                return jsonify({'status': 'success'})
            else:
                return jsonify({'status': 'error', 'message': '删除数据失败，数据库操作异常'}), 500
        except Exception as e:
            print(f"删除数据时数据库错误: {e}")
            return jsonify({'status': 'error', 'message': '删除数据失败，请联系管理员'}), 500

@bp.route('/api/data/<int:data_id>', methods=['GET'])
@login_required
def get_data_by_id(data_id):
    db = Database()
    
    data = db.get_data_by_id(data_id)
    if not data:
        return jsonify({'status': 'error', 'message': '数据不存在'}), 404
    
    return jsonify({
        'status': 'success',
        'data': {
            'data_id': data[0],
            'data_name': data[1],
            'data_type': data[2],
            'content': data[3],
            'creator': data[4],  
            'create_time': data[5],
            'update_time': data[6]
        }
    })

@bp.errorhandler(404)
def page_not_found(e):
    if 'user' in session:
        return render_template('404.html'), 404
    return redirect('/')

@bp.errorhandler(403)
def forbidden(e):
    if 'user' in session:
        return render_template('403.html'), 403
    return redirect('/')

                    """
                },
                {
                    "role": "user",
                    "content": question
                }
            ],
            "temperature": 0.7,
            "max_tokens": 1000
        }
        
        # 调用DeepSeek API（添加超时和错误处理）
        response = requests.post(
            DEEPSEEK_API_URL,
            headers=headers,
            json=payload,
            timeout=30  # 30秒超时
        )
        response.raise_for_status()  # 检查HTTP错误
        
        result = response.json()
        
        # 提取回答内容
        if 'choices' in result and len(result['choices']) > 0:
            answer = result['choices'][0]['message']['content']
            return jsonify({
                'status': 'success',
                'answer': answer
            })
        else:
            raise Exception("API响应格式不正确")
        
    except requests.exceptions.RequestException as e:
        error_msg = f'AI服务请求失败: {str(e)}'
        if hasattr(e, 'response') and e.response:
            try:
                error_details = e.response.json()
                error_msg += f" | 详情: {error_details.get('message', '无')}"
            except:
                error_msg += f" | 状态码: {e.response.status_code}"
        return jsonify({'status': 'error', 'message': error_msg}), 500
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'处理AI请求时出错: {str(e)}'
        }), 500

# 用户API路由 - 仅管理员可访问
@bp.route('/api/users', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
@role_required(ROLE_ADMIN)
def users_api():
    # 保持原有逻辑不变
    db = Database()
    
    if request.method == 'GET':
        condition = request.args.get('q', '')
        if condition.isdigit():  # 如果传入的是数字，认为是用户 ID，进行精确匹配
            user = db.get_user_by_id(int(condition))
            if user:
                return jsonify({
                    'status': 'success',
                    'data': [{
                        'user_id': user['user_id'],
                        'username': user['username'],
                        'role': user['role'],
                        'create_time': user['create_time']
                    }]
                })
            return jsonify({'status': 'success', 'data': []})
        else:  # 否则进行模糊搜索
            users = db.get_user_list(condition)
            return jsonify({
                'status': 'success',
                'data': [{
                    'user_id': u[0],
                    'username': u[1],
                    'role': u[2],
                    'create_time': u[3]
                } for u in users]
            })
    
    elif request.method == 'POST':
        data = request.json
        if not all(key in data for key in ['username', 'password', 'role']):
            return jsonify({'status': 'error', 'message': '缺少必要字段'}), 400
            
        user_id = db.add_user(data)
        if user_id:
            return jsonify({
                'status': 'success',
                'data': {'user_id': user_id}
            })
        return jsonify({'status': 'error', 'message': '创建用户失败'}), 500
    
    elif request.method == 'PUT':
        data = request.json
        if not all(key in data for key in ['user_id', 'username', 'role']):
            return jsonify({'status': 'error', 'message': '缺少必要字段'}), 400
            
        if db.update_user(data) is not None:
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': '更新用户失败'}), 500
    
    elif request.method == 'DELETE':
        user_id = request.json.get('user_id')
        if not user_id:
            return jsonify({'status': 'error', 'message': '缺少用户 ID'}), 400
            
        if db.delete_user(user_id) is not None:
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': '删除用户失败'}), 500

@bp.route('/api/users/<int:user_id>', methods=['GET'])
@login_required
@role_required(ROLE_ADMIN)
def get_single_user(user_id):
    # 保持原有逻辑不变
    db = Database()
    user = db.get_user_by_id(user_id)
    if user:
        return jsonify({
            'status': 'success',
            'data': {
                'user_id': user['user_id'],
                'username': user['username'],
                'role': user['role'],
                'create_time': user['create_time']
            }
        })
    return jsonify({'status': 'error', 'message': '用户不存在'}), 404

# 数据API路由 - 根据角色控制权限
@bp.route('/api/data', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def data_api():
    db = Database()
    user_id = session['user']['user_id']
    user_role = session['user']['role']
    
    if request.method == 'GET':
        condition = request.args.get('q', '')
        # 所有角色都可以查看所有数据，不再传递 user_id
        data = db.get_data_list(condition)
        
        # 为每个数据项添加权限标志
        result = []
        for d in data:
            data_item = {
                'data_id': d[0],
                'data_name': d[1],
                'data_type': d[2],
                'content': d[3],
                'creator': d[4],  # 假设d[4]是creator的用户名
                'create_time': d[5],
                'update_time': d[6],
                # 权限控制
                'can_edit': user_role == ROLE_ADMIN or user_role == ROLE_DESIGNER,
                'can_delete': user_role == ROLE_ADMIN or user_role == ROLE_DESIGNER,
            }
            result.append(data_item)
        
        return jsonify({
            'status': 'success',
            'data': result,
            'total': len(result)  # 暂时使用这个，实际应该从数据库获取总数
        })
    
    elif request.method in ['POST', 'PUT']:  # 合并POST和PUT的处理逻辑
        data = request.json
        # 强制校验必要字段，避免空值导致的创建失败
        required_fields = ['data_name', 'data_type', 'content']
        if not all(key in data for key in required_fields):
            missing = ', '.join([f"'{k}'" for k in required_fields if k not in data])
            return jsonify({'status': 'error', 'message': f'缺少必要字段: {missing}'}), 400
            
        # 权限控制：use不能添加数据，designer和admin可以添加
        if user_role == ROLE_USER :
            return jsonify({'status': 'error', 'message': '无权限操作'}), 403
        
        if request.method == 'POST':
            # 添加新数据
            new_data = db.add_data(data, user_id)
            if new_data:
                return jsonify({
                    'status': 'success',
                    'data': {
                        'data_id': new_data[0],
                        'data_name': new_data[1],
                        'data_type': new_data[2],
                        'content': new_data[3],
                        'creator': new_data[4],
                        'create_time': new_data[5],
                        'update_time': new_data[6]
                    }
                })
        else:  # PUT请求
            data_id = data.get('data_id')
            if not data_id:
                return jsonify({'status': 'error', 'message': '缺少数据ID'}), 400
                
            db_data = db.get_data_by_id(data_id)
            if not db_data:
                return jsonify({'status': 'error', 'message': '数据不存在'}), 404
                
            
            if user_role == ROLE_USER:
                return jsonify({'status': 'error', 'message': '无权限编辑数据'}), 403          
            
            updated_data = db.update_data(data)
            if updated_data:
                return jsonify({
                    'status': 'success',
                    'data': {
                        'data_id': updated_data[0],
                        'data_name': updated_data[1],
                        'data_type': updated_data[2],
                        'content': updated_data[3],
                        'creator': updated_data[4],
                        'create_time': updated_data[5],
                        'update_time': updated_data[6]
                    }
                })
        
            return jsonify({'status': 'error', 'message': '保存数据失败，请检查数据库连接'}), 500
    
    elif request.method == 'DELETE':
        # 修改为从请求体中获取数据
        data = request.get_json()
        if not data or 'data_id' not in data:
            return jsonify({'status': 'error', 'message': '缺少数据ID'}), 400
            
        data_id = data['data_id']
        db_data = db.get_data_by_id(data_id)
        if not db_data:
            return jsonify({'status': 'error', 'message': '数据不存在'}), 404
            
        # 权限校验 - 确保用户有权限删除数据
        creator_id = db_data[4]  # 假设db_data[4]是creator_id
        if user_role == ROLE_USER:
            return jsonify({'status': 'error', 'message': '无权限删除数据'}), 403
        
            
        try:
            delete_result = db.delete_data(data_id)
            if delete_result is not None:
                return jsonify({'status': 'success'})
            else:
                return jsonify({'status': 'error', 'message': '删除数据失败，数据库操作异常'}), 500
        except Exception as e:
            print(f"删除数据时数据库错误: {e}")
            return jsonify({'status': 'error', 'message': '删除数据失败，请联系管理员'}), 500

@bp.route('/api/data/<int:data_id>', methods=['GET'])
@login_required
def get_data_by_id(data_id):
    db = Database()
    
    data = db.get_data_by_id(data_id)
    if not data:
        return jsonify({'status': 'error', 'message': '数据不存在'}), 404
    
    return jsonify({
        'status': 'success',
        'data': {
            'data_id': data[0],
            'data_name': data[1],
            'data_type': data[2],
            'content': data[3],
            'creator': data[4],  
            'create_time': data[5],
            'update_time': data[6]
        }
    })

@bp.errorhandler(404)
def page_not_found(e):
    if 'user' in session:
        return render_template('404.html'), 404
    return redirect('/')

@bp.errorhandler(403)
def forbidden(e):
    if 'user' in session:
        return render_template('403.html'), 403
    return redirect('/')