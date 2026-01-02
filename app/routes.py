from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, Role, Permission
from app.forms import LoginForm, RegisterForm, UserForm
from app.decorators import role_required, permission_required

# Blueprints
main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__)
admin_bp = Blueprint('admin', __name__)

# ==================== RUTAS PRINCIPALES ====================
@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/dashboard')
@login_required
@permission_required('view_dashboard')
def dashboard():
    return render_template('dashboard.html')

# ==================== RUTAS DE AUTENTICACIÓN ====================
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Tu cuenta ha sido desactivada. Contacta al administrador.', 'danger')
                return redirect(url_for('auth.login'))
            
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash(f'¡Bienvenido {user.username}!', 'success')
            return redirect(next_page if next_page else url_for('main.dashboard'))
        else:
            flash('Usuario o contraseña incorrectos.', 'danger')
    
    return render_template('login.html', form=form)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        
        # Asignar rol de usuario por defecto
        user_role = Role.query.filter_by(name='user').first()
        if user_role:
            user.roles.append(user_role)
        
        db.session.add(user)
        db.session.commit()
        
        flash('¡Registro exitoso! Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión exitosamente.', 'info')
    return redirect(url_for('main.index'))

# ==================== RUTAS DE ADMINISTRACIÓN ====================
@admin_bp.route('/users')
@login_required
@permission_required('view_users')
def users():
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(page=page, per_page=10, error_out=False)
    return render_template('admin/users.html', users=users)

@admin_bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@permission_required('create_users')
def create_user():
    form = UserForm()
    form.roles.choices = [(r.id, r.name) for r in Role.query.all()]
    
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, is_active=form.is_active.data)
        if form.password.data:
            user.set_password(form.password.data)
        else:
            user.set_password('changeme123')  # Contraseña temporal
        
        # Asignar roles
        for role_id in form.roles.data:
            role = Role.query.get(role_id)
            if role:
                user.roles.append(role)
        
        db.session.add(user)
        db.session.commit()
        flash('Usuario creado exitosamente.', 'success')
        return redirect(url_for('admin.users'))
    
    return render_template('admin/user_form.html', form=form, action='Crear')

@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@permission_required('edit_users')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserForm(obj=user)
    form.roles.choices = [(r.id, r.name) for r in Role.query.all()]
    
    if request.method == 'GET':
        form.roles.data = [r.id for r in user.roles]
    
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.is_active = form.is_active.data
        
        if form.password.data:
            user.set_password(form.password.data)
        
        # Actualizar roles
        user.roles = []
        for role_id in form.roles.data:
            role = Role.query.get(role_id)
            if role:
                user.roles.append(role)
        
        db.session.commit()
        flash('Usuario actualizado exitosamente.', 'success')
        return redirect(url_for('admin.users'))
    
    return render_template('admin/user_form.html', form=form, action='Editar', user=user)

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@permission_required('delete_users')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'No puedes eliminar tu propia cuenta'}), 400
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Usuario eliminado exitosamente'})

@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@permission_required('edit_users')
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'No puedes desactivar tu propia cuenta'}), 400
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activado' if user.is_active else 'desactivado'
    return jsonify({'success': True, 'message': f'Usuario {status} exitosamente', 'is_active': user.is_active})

@admin_bp.route('/roles')
@login_required
@permission_required('manage_roles')
def roles():
    roles = Role.query.all()
    permissions = Permission.query.all()
    return render_template('admin/roles.html', roles=roles, permissions=permissions)
