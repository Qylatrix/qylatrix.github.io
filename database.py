"""
Database management for user authentication and learning progress
"""
import sqlite3
import hashlib
import secrets
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')

def get_db_connection():
    """Create a database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with required tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table with role support
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            role TEXT DEFAULT 'student',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    ''')
    
    # User progress table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            module_id TEXT NOT NULL,
            lesson_id TEXT NOT NULL,
            completed INTEGER DEFAULT 0,
            completed_at TIMESTAMP,
            progress_percentage INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, module_id, lesson_id)
        )
    ''')
    
    # User notes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            module_id TEXT NOT NULL,
            lesson_id TEXT NOT NULL,
            note_content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # User achievements table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_achievements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            achievement_type TEXT NOT NULL,
            achievement_name TEXT NOT NULL,
            earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Quizzes table (created by employees)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quizzes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            module_id TEXT,
            created_by INTEGER NOT NULL,
            time_limit INTEGER DEFAULT 30,
            passing_score INTEGER DEFAULT 70,
            max_attempts INTEGER DEFAULT 3,
            enable_tab_detection INTEGER DEFAULT 1,
            enable_screenshot_detection INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    ''')
    
    # Quiz questions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quiz_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quiz_id INTEGER NOT NULL,
            question_text TEXT NOT NULL,
            option_a TEXT NOT NULL,
            option_b TEXT NOT NULL,
            option_c TEXT,
            option_d TEXT,
            correct_answer TEXT NOT NULL,
            points INTEGER DEFAULT 1,
            FOREIGN KEY (quiz_id) REFERENCES quizzes (id)
        )
    ''')
    
    # Quiz attempts table (student submissions)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quiz_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quiz_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP,
            score INTEGER,
            total_questions INTEGER,
            passed INTEGER DEFAULT 0,
            tab_switches INTEGER DEFAULT 0,
            screenshot_attempts INTEGER DEFAULT 0,
            auto_submitted INTEGER DEFAULT 0,
            answers_json TEXT,
            FOREIGN KEY (quiz_id) REFERENCES quizzes (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    # Contact messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contact_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            subject TEXT,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read INTEGER DEFAULT 0
        )
    ''')
    

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")
    
    # Create default guest user
    create_default_guest_user()

def create_default_guest_user():
    """Create a default guest/admin user for easy access"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if admin user already exists
        cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
        if cursor.fetchone():
            conn.close()
            print("ℹ️  Guest user 'admin' already exists")
            return
        
        # Create admin guest user as employee
        password_hash = hash_password('password')
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', 'admin@guest.local', password_hash, 'Admin Employee', 'employee'))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        print("✅ Default guest user created!")
        print("   Username: admin")
        print("   Password: password")
        return user_id
    except Exception as e:
        print(f"⚠️  Could not create guest user: {e}")
        return None


def hash_password(password):
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def create_user(username, email, password, full_name=None):
    """Create a new user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        password_hash = hash_password(password)
        
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, full_name)
            VALUES (?, ?, ?, ?)
        ''', (username, email, password_hash, full_name))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return {"success": True, "user_id": user_id}
    except sqlite3.IntegrityError as e:
        return {"success": False, "error": "Username or email already exists"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def verify_user(username, password):
    """Verify user credentials"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    password_hash = hash_password(password)
    
    cursor.execute('''
        SELECT * FROM users 
        WHERE username = ? AND password_hash = ? AND is_active = 1
    ''', (username, password_hash))
    
    user = cursor.fetchone()
    
    if user:
        # Update last login
        cursor.execute('''
            UPDATE users SET last_login = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (user['id'],))
        conn.commit()
    
    conn.close()
    return dict(user) if user else None

def get_user_by_id(user_id):
    """Get user information by ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    conn.close()
    return dict(user) if user else None

def update_user_progress(user_id, module_id, lesson_id, completed=False, progress=0):
    """Update user's learning progress"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO user_progress 
            (user_id, module_id, lesson_id, completed, completed_at, progress_percentage)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user_id, 
            module_id, 
            lesson_id, 
            1 if completed else 0,
            datetime.now() if completed else None,
            progress
        ))
        
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}

def get_user_progress(user_id):
    """Get all progress for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM user_progress 
        WHERE user_id = ?
        ORDER BY completed_at DESC
    ''', (user_id,))
    
    progress = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return progress

def add_user_achievement(user_id, achievement_type, achievement_name):
    """Add an achievement for a user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO user_achievements (user_id, achievement_type, achievement_name)
            VALUES (?, ?, ?)
        ''', (user_id, achievement_type, achievement_name))
        
        conn.commit()
        conn.close()
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}

def get_user_achievements(user_id):
    """Get all achievements for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM user_achievements 
        WHERE user_id = ?
        ORDER BY earned_at DESC
    ''', (user_id,))
    
    achievements = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return achievements

def get_user_stats(user_id):
    """Get user statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get total lessons completed
    cursor.execute('''
        SELECT COUNT(*) as completed_lessons
        FROM user_progress
        WHERE user_id = ? AND completed = 1
    ''', (user_id,))
    completed = cursor.fetchone()['completed_lessons']
    
    # Get total achievements
    cursor.execute('''
        SELECT COUNT(*) as total_achievements
        FROM user_achievements
        WHERE user_id = ?
    ''', (user_id,))
    achievements = cursor.fetchone()['total_achievements']
    
    # Get total learning time (estimate based on lessons)
    learning_time = completed * 15  # Assume 15 minutes per lesson
    
    conn.close()
    
    return {
        'completed_lessons': completed,
        'total_achievements': achievements,
        'learning_time_minutes': learning_time
    }

def save_contact_message(name, email, subject, message):
    """Save a contact form message"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO contact_messages (name, email, subject, message)
            VALUES (?, ?, ?, ?)
        ''', (name, email, subject, message))
        
        conn.commit()
        message_id = cursor.lastrowid
        conn.close()
        return {"success": True, "message_id": message_id}
    except Exception as e:
        return {"success": False, "error": str(e)}

def get_all_contact_messages():
    """Get all contact messages"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM contact_messages 
        ORDER BY created_at DESC
    ''')
    
    messages = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return messages

# Initialize database on module import
if __name__ == "__main__":
    init_db()
