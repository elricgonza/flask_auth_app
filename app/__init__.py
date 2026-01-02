from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Inicializar extensiones
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    
    # Configurar login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor inicia sesión para acceder a esta página.'
    login_manager.login_message_category = 'info'
    
    # Importar modelos y rutas
    from app import models
    from app.routes import main_bp, auth_bp, admin_bp
    
    # Registrar blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    
    # Crear tablas y datos iniciales
    with app.app_context():
        db.create_all()
        init_default_data()
    
    return app

def init_default_data():
    from app.models import User, Role, Permission
    
    permissions_data = [
        ('view_users', 'Ver usuarios'),
        ('create_users', 'Crear usuarios'),
        ('edit_users', 'Editar usuarios'),
        ('delete_users', 'Eliminar usuarios'),
        ('manage_roles', 'Gestionar roles'),
        ('view_dashboard', 'Ver dashboard'),
    ]
    
    for perm_name, perm_desc in permissions_data:
        if not Permission.query.filter_by(name=perm_name).first():
            permission = Permission(name=perm_name, description=perm_desc)
            db.session.add(permission)
    
    db.session.commit()
    
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role(name='admin', description='Administrador del sistema')
        all_permissions = Permission.query.all()
        admin_role.permissions = all_permissions
        db.session.add(admin_role)
    
    user_role = Role.query.filter_by(name='user').first()
    if not user_role:
        user_role = Role(name='user', description='Usuario estándar')
        view_dashboard = Permission.query.filter_by(name='view_dashboard').first()
        if view_dashboard:
            user_role.permissions.append(view_dashboard)
        db.session.add(user_role)
    
    db.session.commit()
    
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', email='admin@example.com')
        admin_user.set_password('admin123')
        admin_user.roles.append(admin_role)
        db.session.add(admin_user)
        db.session.commit()
        print('Usuario admin creado: admin / admin123')
