import os
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime, timedelta
import json
from math import ceil
from types import SimpleNamespace
from collections import defaultdict

# Importações diretas do MongoEngine
from mongoengine import connect, Document, StringField, EmailField, ReferenceField, DateTimeField, FloatField
from mongoengine.errors import NotUniqueError

# Carrega as variáveis de ambiente do arquivo .env
load_dotenv()

# --- CONFIGURAÇÃO ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'uma-chave-secreta-padrao-para-dev')
connect(host=os.environ.get('MONGODB_URI'))

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça o login para acessar esta página.'
login_manager.login_message_category = 'info'

@app.context_processor
def inject_year():
    return {'current_year': datetime.utcnow().year}

# --- MODELOS COM MONGOENGINE ---
class User(Document, UserMixin):
    email = EmailField(required=True, unique=True)
    name = StringField(required=True, unique=True)
    password_hash = StringField(required=True)
    role = StringField(required=True, default='agent')
    def get_id(self): return str(self.id)

class Commission(Document):
    user = ReferenceField(User, required=True, reverse_delete_rule=4) # CASCADE on delete
    date = DateTimeField(required=True)
    client = StringField(required=True)
    subprocess = StringField(required=True)
    value = FloatField(required=True)
    sector = StringField()
    meta = {'indexes': ['date', 'user']}

class SubprocessValue(Document):
    name = StringField(required=True, unique=True)
    value = FloatField(required=True)
    meta = {'indexes': ['name']}

@login_manager.user_loader
def load_user(user_id):
    return User.objects(id=user_id).first()

# --- ROTAS BÁSICAS E DASHBOARDS ---
@app.route('/')
def index():
    if not current_user.is_authenticated: return redirect(url_for('login'))
    if current_user.role in ['admin', 'superadmin']: return redirect(url_for('admin_dashboard'))
    else: return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.objects(email=request.form.get('email')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        else: flash('Login inválido.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'agent': return redirect(url_for('admin_dashboard'))
    today = datetime.utcnow()
    start_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    next_month = start_of_month.replace(day=28) + timedelta(days=4)
    end_of_month = next_month - timedelta(days=next_month.day)
    end_of_month = end_of_month.replace(hour=23, minute=59, second=59)
    commissions_this_month = Commission.objects(user=current_user.id, date__gte=start_of_month, date__lte=end_of_month).order_by('-date')
    stats = {'total_commission': sum(c.value for c in commissions_this_month), 'total_attendances': len(commissions_this_month)}
    subprocess_counts = defaultdict(int)
    for c in commissions_this_month: subprocess_counts[c.subprocess] += 1
    chart_labels = list(subprocess_counts.keys())
    chart_values = list(subprocess_counts.values())
    return render_template('dashboard.html', commissions=commissions_this_month, stats=stats, chart_labels=chart_labels, chart_values=chart_values)

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role not in ['admin', 'superadmin']: return redirect(url_for('dashboard'))
    stats = {'total_users': User.objects.count(), 'total_subprocesses': SubprocessValue.objects.count(), 'total_commissions': Commission.objects.count(), 'total_value': Commission.objects.sum('value') or 0}
    today = datetime.utcnow().date()
    seven_days_ago = today - timedelta(days=6)
    weekly_counts = {(seven_days_ago + timedelta(days=i)): 0 for i in range(7)}
    recent_commissions = Commission.objects(date__gte=datetime.combine(seven_days_ago, datetime.min.time()))
    for c in recent_commissions:
        if c.date.date() in weekly_counts: weekly_counts[c.date.date()] += 1
    chart_labels = [day.strftime('%d/%m') for day in weekly_counts.keys()]
    chart_values = list(weekly_counts.values())
    return render_template('admin_dashboard.html', stats=stats, chart_labels=chart_labels, chart_values=chart_values)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/profile/update-password', methods=['POST'])
@login_required
def update_password():
    current_password, new_password, confirm_password = request.form.get('current_password'), request.form.get('new_password'), request.form.get('confirm_password')
    if not check_password_hash(current_user.password_hash, current_password):
        flash('Sua senha atual está incorreta.', 'danger')
    elif new_password != confirm_password:
        flash('A nova senha e a confirmação não coincidem.', 'danger')
    elif len(new_password) < 4:
        flash('A nova senha deve ter pelo menos 4 caracteres.', 'warning')
    else:
        current_user.password_hash = generate_password_hash(new_password)
        current_user.save()
        flash('Sua senha foi alterada com sucesso!', 'success')
    return redirect(url_for('profile'))

@app.route('/upload/spreadsheet')
@login_required
def upload_page():
    if current_user.role not in ['admin', 'superadmin']: return redirect(url_for('dashboard'))
    return render_template('upload_page.html')

@app.route('/upload/process', methods=['POST'])
@login_required
def upload_process():
    if current_user.role not in ['admin', 'superadmin']: return redirect(url_for('dashboard'))
    file = request.files.get('file')
    if not file or not file.filename:
        flash('Nenhum arquivo selecionado.', 'warning')
        return redirect(url_for('upload_page'))
    try:
        df = pd.read_csv(file) if file.filename.endswith('.csv') else pd.read_excel(file)
        subprocess_values = {sp.name.strip().lower(): sp.value for sp in SubprocessValue.objects.all()}
        added, ignored_user, ignored_sp, duplicates = 0, 0, 0, 0
        for _, row in df.iterrows():
            created_at = pd.to_datetime(row.get('Criado em'), format='%Y-%m-%d %H:%M:%S')
            op_name, sp_name, client = row.get('Usuário'), row.get('Assunto'), str(row.get('Cliente', 'N/A'))
            if pd.isna(op_name) or pd.isna(sp_name) or pd.isna(created_at): continue
            user = User.objects(name=op_name).first()
            if not user: ignored_user += 1; continue
            clean_sp = str(sp_name).strip().lower()
            sp_val = subprocess_values.get(clean_sp)
            if sp_val is None: ignored_sp += 1; continue
            if not Commission.objects(user=user, date=created_at, client=client, subprocess=str(sp_name).strip()).first():
                Commission(user=user, date=created_at, client=client, subprocess=str(sp_name).strip(), value=float(sp_val), sector=str(row.get('Departamento')) if pd.notna(row.get('Departamento')) else None).save()
                added += 1
            else:
                duplicates += 1
        if added > 0: flash(f'Planilha processada! {added} novas comissões adicionadas.', 'success')
        if duplicates > 0: flash(f'{duplicates} linhas ignoradas por duplicidade.', 'info')
        if ignored_user > 0: flash(f'{ignored_user} linhas ignoradas por usuário não encontrado.', 'warning')
        if ignored_sp > 0: flash(f'{ignored_sp} linhas ignoradas por subprocesso sem valor.', 'warning')
        if added == 0 and duplicates == 0 and ignored_user == 0 and ignored_sp == 0: flash('Planilha processada, mas nenhum registro válido encontrado.', 'secondary')
    except Exception as e:
        flash(f'Erro ao processar a planilha: {e}', 'danger')
    return redirect(url_for('upload_page'))
    
@app.route('/reports')
@login_required
def reports():
    if current_user.role not in ['admin', 'superadmin']: return redirect(url_for('dashboard'))
    user_filter = request.args.get('user_id')
    sector_filter = request.args.get('sector')
    subprocess_filter = request.args.get('subprocess')
    start_date_filter = request.args.get('start_date')
    end_date_filter = request.args.get('end_date')
    query_filters = {}
    if user_filter: query_filters['user'] = user_filter
    if sector_filter: query_filters['sector'] = sector_filter
    if subprocess_filter: query_filters['subprocess'] = subprocess_filter
    if start_date_filter: query_filters['date__gte'] = start_date_filter
    if end_date_filter: query_filters['date__lte'] = end_date_filter
    
    filtered_commissions = Commission.objects(**query_filters).order_by('-date').select_related()
    
    attendances_by_operator = defaultdict(int)
    attendances_by_subprocess = defaultdict(int)
    for c in filtered_commissions:
        attendances_by_operator[c.user.name] += 1
        attendances_by_subprocess[c.subprocess] += 1
    
    operators = User.objects(role__in=['agent', 'admin', 'superadmin']).order_by('name')
    sectors = Commission.objects.distinct('sector')
    subprocesses = SubprocessValue.objects.order_by('name')

    return render_template('reports.html',
        total_attendances=len(filtered_commissions),
        total_value=sum(c.value for c in filtered_commissions),
        attendances_by_operator=dict(attendances_by_operator),
        attendances_by_subprocess=dict(attendances_by_subprocess),
        operators=operators, sectors=sectors, subprocesses=subprocesses,
        filters={
            'user_id': user_filter, 'sector': sector_filter, 'subprocess': subprocess_filter,
            'start_date': start_date_filter, 'end_date': end_date_filter
        }
    )

@app.route('/manage/users')
@login_required
def manage_users():
    if current_user.role not in ['admin', 'superadmin']: return redirect(url_for('index'))
    return render_template('manage_users.html', users=User.objects.order_by('name'))

@app.route('/manage/subprocesses')
@login_required
def manage_subprocesses():
    if current_user.role not in ['admin', 'superadmin']: return redirect(url_for('dashboard'))
    return render_template('manage_subprocesses.html', subprocesses=SubprocessValue.objects.order_by('name'))

@app.route('/manage/commissions')
@login_required
def manage_commissions():
    if current_user.role not in ['admin', 'superadmin']: return redirect(url_for('index'))
    page = request.args.get('page', 1, type=int)
    per_page = 30
    user_filter, sector_filter, start_date, end_date = request.args.get('user_id'), request.args.get('sector'), request.args.get('start_date'), request.args.get('end_date')
    query_filters = {}
    if user_filter: query_filters['user'] = user_filter
    if sector_filter: query_filters['sector'] = sector_filter
    if start_date: query_filters['date__gte'] = start_date
    if end_date: query_filters['date__lte'] = end_date
    query = Commission.objects(**query_filters)
    total = query.count()
    items = query.order_by('-date').skip((page - 1) * per_page).limit(per_page)
    pagination = SimpleNamespace(items=items, page=page, per_page=per_page, total=total, pages=int(ceil(total / per_page)), has_prev=(page > 1), has_next=(page * per_page < total), prev_num=page - 1, next_num=page + 1, iter_pages=lambda left_edge=2, right_edge=2, left_current=2, right_current=5: range(1, int(ceil(total / per_page)) + 1))
    operators = User.objects(role__in=['agent', 'admin', 'superadmin']).order_by('name')
    sectors = Commission.objects.distinct('sector')
    filters = {'user_id': user_filter, 'sector': sector_filter, 'start_date': start_date, 'end_date': end_date}
    return render_template('manage_commissions.html', pagination=pagination, operators=operators, sectors=sectors, filters=filters)

@app.route('/commission/delete/<id>', methods=['POST'])
@login_required
def delete_commission(id):
    if current_user.role not in ['admin', 'superadmin']: return redirect(url_for('index'))
    Commission.objects.get(id=id).delete()
    flash('Registro removido!', 'success')
    return redirect(request.referrer or url_for('manage_commissions'))

@app.route('/commission/delete/bulk', methods=['POST'])
@login_required
def delete_commission_bulk():
    if current_user.role not in ['admin', 'superadmin']: return redirect(url_for('index'))
    ids = request.form.getlist('commission_ids')
    if not ids:
        flash('Nenhum registro selecionado.', 'warning')
    else:
        Commission.objects(id__in=ids).delete()
        flash(f'{len(ids)} registros removidos!', 'success')
    return redirect(url_for('manage_commissions'))

@app.route('/user/add', methods=['POST'])
@login_required
def add_user():
    # ... (código da rota add_user)
    pass

@app.route('/user/edit/<id>', methods=['POST'])
@login_required
def edit_user(id):
    # ... (código da rota edit_user)
    pass

@app.route('/user/delete/<id>', methods=['POST'])
@login_required
def delete_user(id):
    # ... (código da rota delete_user)
    pass

@app.route('/user/change-password/<id>', methods=['POST'])
@login_required
def change_password(id):
    # ... (código da rota change_password)
    pass

@app.route('/subprocess/add', methods=['POST'])
@login_required
def add_subprocess():
    # ... (código da rota add_subprocess)
    pass

@app.route('/subprocess/edit/<id>', methods=['POST'])
@login_required
def edit_subprocess(id):
    # ... (código da rota edit_subprocess)
    pass

@app.route('/subprocess/delete/<id>', methods=['POST'])
@login_required
def delete_subprocess(id):
    # ... (código da rota delete_subprocess)
    pass
    
@app.route('/setup/create-first-superadmin')
def create_first_superadmin():
    # ... (código da rota de setup)
    pass

if __name__ == '__main__':
    app.run(debug=True)