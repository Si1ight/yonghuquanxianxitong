import sqlite3
import hashlib
import datetime

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('instance/user_permission.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
    
    def __del__(self):
        self.conn.close()
    
    def execute_query(self, query, params=()):
        try:
            self.cursor.execute(query, params)
            return self.cursor.fetchall()
        except sqlite3.Error as e:
            print(f"数据库查询错误: {e}")
            return None
    
    def execute_update(self, query, params=()):
        try:
            self.cursor.execute(query, params)
            self.conn.commit()
            return self.cursor.lastrowid
        except sqlite3.Error as e:
            print(f"数据库更新错误: {e}")
            self.conn.rollback()
            return None
    
    def get_user_by_username(self, username):
        result = self.execute_query('SELECT * FROM users WHERE username = ?', (username,))
        if result:
            user_data = result[0]
            return {
                'user_id': user_data[0],
                'username': user_data[1],
                'password': user_data[2],
                'role': user_data[3],
                'create_time': user_data[4]
            }
        return None
    
    def get_user_by_id(self, user_id):
        result = self.execute_query('SELECT * FROM users WHERE user_id = ?', (user_id,))
        if result:
            user_data = result[0]
            return {
                'user_id': user_data[0],
                'username': user_data[1],
                'password': user_data[2],
                'role': user_data[3],
                'create_time': user_data[4]
            }
        return None
    
    def get_user_list(self, condition=''):
        query = 'SELECT user_id, username, role, create_time FROM users'
        if condition:
            query += f" WHERE username LIKE '%{condition}%' OR role LIKE '%{condition}%'"
        return self.execute_query(query)
    
    def add_user(self, user):
        password_hash = hashlib.sha256(user['password'].encode()).hexdigest()
        return self.execute_update(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            (user['username'], password_hash, user['role'])
        )
    
    def update_user(self, user):
        password_hash = hashlib.sha256(user['password'].encode()).hexdigest() if user.get('password') else None
        if password_hash:
            query = 'UPDATE users SET username = ?, password = ?, role = ? WHERE user_id = ?'
            params = (user['username'], password_hash, user['role'], user['user_id'])
        else:
            query = 'UPDATE users SET username = ?, role = ? WHERE user_id = ?'
            params = (user['username'], user['role'], user['user_id'])
        return self.execute_update(query, params)
    
    def delete_user(self, user_id):
        return self.execute_update('DELETE FROM users WHERE user_id = ?', (user_id,))
    
    def get_data_list(self, condition=''):  # 移除 user_id 参数
        query = 'SELECT d.data_id, d.data_name, d.data_type, d.content, '
        query += 'u.username, d.create_time, d.update_time '
        query += 'FROM data d JOIN users u ON d.creator_id = u.user_id '
        
        conditions = []
        if condition:
            conditions.append(f"(d.data_name LIKE '%{condition}%' OR d.data_type LIKE '%{condition}%')")
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        return self.execute_query(query)    
    
    def get_data_by_id(self, data_id):
        result = self.execute_query(
            'SELECT d.data_id, d.data_name, d.data_type, d.content, '
            'u.username, d.create_time, d.update_time '
            'FROM data d JOIN users u ON d.creator_id = u.user_id '
            'WHERE d.data_id = ?', 
            (data_id,)
        )
        if result:
            return result[0]
        return None
    
    def add_data(self, data, user_id):
        result = self.execute_update(
            'INSERT INTO data (data_name, data_type, content, creator_id) VALUES (?, ?, ?, ?)',
            (data['data_name'], data['data_type'], data['content'], user_id)
        )
        if result:
            return self.get_data_by_id(result)
        return None
    
    def update_data(self, data):
        self.execute_update(
            'UPDATE data SET data_name = ?, data_type = ?, content = ?, update_time = ? WHERE data_id = ?',
            (data['data_name'], data['data_type'], data['content'], datetime.datetime.now(), data['data_id'])
        )
        return self.get_data_by_id(data['data_id'])
    
    def delete_data(self, data_id):
        return self.execute_update('DELETE FROM data WHERE data_id = ?', (data_id,))

def init_database():
    conn = sqlite3.connect('instance/user_permission.db')
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS data (
        data_id INTEGER PRIMARY KEY AUTOINCREMENT,
        data_name TEXT NOT NULL,
        data_type TEXT NOT NULL,
        content TEXT,
        creator_id INTEGER,
        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        update_time TIMESTAMP,
        FOREIGN KEY (creator_id) REFERENCES users (user_id)
    )
    ''')
    
    # 插入测试用户（密码已哈希）
    test_users = [
        ('admin', hashlib.sha256('admin123'.encode()).hexdigest(), 'admin'),
        ('designer', hashlib.sha256('designer123'.encode()).hexdigest(), 'designer'),
        ('user', hashlib.sha256('user123'.encode()).hexdigest(), 'user')
    ]
    cursor.executemany(
        'INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
        test_users
    )
    
    conn.commit()
    conn.close()