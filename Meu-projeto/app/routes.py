from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import current_user, login_user, logout_user, login_required
from .forms import LoginForm, CadastroForm
from .models import User
from . import db, security, utils

auth = Blueprint('auth', __name__)
profile = Blueprint('profile', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile.perfil'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and security.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = utils.get_next_page()
            return redirect(next_page) if next_page else redirect(url_for('profile.perfil'))
        else:
            flash('Login inválido. Verifique seu e-mail e senha.', 'danger')
    return render_template('login.html', form=form)

@auth.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if current_user.is_authenticated:
        return redirect(url_for('profile.perfil'))
    form = CadastroForm()
    if form.validate_on_submit():
        hashed_password = security.generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Sua conta foi criada! Agora você pode fazer login.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('cadastro.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@profile.route('/perfil')
@login_required
def perfil():
    return render_template('perfil.html')

@profile.route('/formulario')
@login_required
def formulario():
    # Lógica para listar formulários do usuário atual
    return render_template('formulario.html')

@profile.route('/formulario/editar/<int:form_id>', methods=['GET', 'POST'])
@login_required
def editar_formulario(form_id):
    # Lógica para editar formulários do usuário atual
    return render_template('editar_formulario.html')
