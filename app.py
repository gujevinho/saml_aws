from flask import Flask, render_template, request, redirect, url_for, session, flash
from saml_utils import SAMLResponseGenerator, validate_user_credentials, get_user_role
from config import Config
import logging

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route('/')
def index():
    """Página inicial - redireciona para login se não autenticado"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Página de login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember')
        
        # Validar credenciais
        if validate_user_credentials(username, password):
            session['username'] = username
            session.permanent = True if remember else False
            
            logger.info(f'Usuário autenticado: {username}')
            flash('Login realizado com sucesso!', 'success')
            
            # Redirecionar para dashboard ou página de destino
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            logger.warning(f'Tentativa de login falhou: {username}')
            flash('Credenciais inválidas!', 'error')
    
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    """Dashboard após login"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    role_arn = get_user_role(username)
    
    return render_template('dashboard.html', 
                         username=username,
                         role_arn=role_arn,
                         aws_account_id=app.config['AWS_ACCOUNT_ID'])


@app.route('/aws/login')
def aws_login():
    """Gera SAML Response e redireciona para AWS"""
    if 'username' not in session:
        flash('Faça login primeiro!', 'error')
        return redirect(url_for('login'))
    
    username = session['username']
    role_arn = get_user_role(username)
    
    if not role_arn:
        flash('Usuário não tem permissão para acessar a AWS!', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Gerar SAML Response
        saml_gen = SAMLResponseGenerator()
        saml_response = saml_gen.generate_saml_response(
            username=username,
            role_arn=role_arn,
            session_name=username.split('@')[0] if '@' in username else username
        )
        
        logger.info(f'SAML Response gerado para: {username}')
        
        # Renderizar página com POST automático para AWS
        return render_template('saml_post.html',
                             saml_response=saml_response,
                             aws_endpoint=app.config['AWS_SAML_ENDPOINT'],
                             relay_state=app.config['RELAY_STATE'])
    
    except Exception as e:
        logger.error(f'Erro ao gerar SAML Response: {str(e)}')
        flash(f'Erro ao acessar AWS: {str(e)}', 'error')
        return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    """Logout do usuário"""
    session.clear()
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('login'))


@app.route('/health')
def health():
    """Endpoint de health check"""
    return {'status': 'ok', 'service': 'AWS SAML IdP'}


if __name__ == '__main__':
    print("=" * 60)
    print("🚀 AWS SAML Identity Provider Intermediário")
    print("=" * 60)
    print(f"🌐 URL Base: {app.config['BASE_URL']}")
    print(f"🔐 Entity ID: {app.config['IDP_ENTITY_ID']}")
    print(f"🎯 AWS Endpoint: {app.config['AWS_SAML_ENDPOINT']}")
    print("=" * 60)
    print("\n📝 Usuários de teste:")
    print("  admin@empresa.com / admin123")
    print("  dev@empresa.com / dev123")
    print("  user@empresa.com / user123")
    print("\n" + "=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)