import base64
import uuid
from datetime import datetime, timedelta
import os
from config import Config
import subprocess
import logging

logger = logging.getLogger(__name__)

class SAMLResponseGenerator:
    """Gera SAML Response para autenticação AWS"""

    def __init__(self):
        self.config = Config()
        # Chama a função para garantir que o diretório existe
        Config.ensure_cert_dir_exists()

        # Verificar e gerar certificados se não existirem
        if not os.path.exists(self.config.CERT_FILE) or not os.path.exists(self.config.KEY_FILE):
            logger.info("Certificados não encontrados, gerando...")
            self._generate_certificates()

        # Carregar certificado e chave privada
        try:
            with open(self.config.CERT_FILE, 'r') as f:
                self.certificate = f.read()

            with open(self.config.KEY_FILE, 'r') as f:
                self.private_key = f.read()
        except FileNotFoundError:
            raise Exception("Certificados não encontrados. Execute setup_certificates() primeiro.")

    def generate_saml_response(self, username, role_arn, session_name=None):
        """
        Gera um SAML Response válido para AWS

        Args:
            username: Nome do usuário
            role_arn: ARN da role AWS
            session_name: Nome da sessão (opcional)

        Returns:
            SAML Response codificado em base64
        """
        if session_name is None:
            session_name = username

        # Gerar IDs únicos
        issue_instant = datetime.utcnow()
        assertion_id = f'_uuid-{uuid.uuid4()}'
        response_id = f'_uuid-{uuid.uuid4()}'
        issuer = self.config.SAML_PROVIDER_NAME

        # Gerar SAML Provider ARN
        saml_provider_arn = f'arn:aws:iam::{self.config.AWS_ACCOUNT_ID}:saml-provider/{issuer}'

        # Template SAML Response (sem assinatura para simplificação inicial)
        saml_template = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{response_id}"
                Version="2.0"
                IssueInstant="{issue_instant.strftime('%Y-%m-%dT%H:%M:%SZ')}">
    <saml:Issuer>{self.config.IDP_ENTITY_ID}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xmlns:xs="http://www.w3.org/2001/XMLSchema"
                   ID="{assertion_id}"
                   Version="2.0"
                   IssueInstant="{issue_instant.strftime('%Y-%m-%dT%H:%M:%SZ')}">
        <saml:Issuer>{self.config.IDP_ENTITY_ID}</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
                {username}
            </saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData
                    NotOnOrAfter="{(issue_instant + timedelta(minutes=self.config.SAML_EXPIRATION_MINUTES)).strftime('%Y-%m-%dT%H:%M:%SZ')}"
                    Recipient="{self.config.AWS_SAML_ENDPOINT}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions
            NotBefore="{(issue_instant - timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')}"
            NotOnOrAfter="{(issue_instant + timedelta(minutes=self.config.SAML_EXPIRATION_MINUTES)).strftime('%Y-%m-%dT%H:%M:%SZ')}">
            <saml:AudienceRestriction>
                <saml:Audience>urn:amazon:webservices</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement
            AuthnInstant="{issue_instant.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            SessionIndex="{assertion_id}">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>
                    urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
                </saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
                <saml:AttributeValue xsi:type="xs:string">
                    {role_arn},{saml_provider_arn}
                </saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
                <saml:AttributeValue xsi:type="xs:string">{session_name}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration">
                <saml:AttributeValue xsi:type="xs:string">3600</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>"""

        # Codificar em base64
        saml_response_encoded = base64.b64encode(saml_template.encode('utf-8')).decode('utf-8')

        return saml_response_encoded

    def _generate_certificates(self):
        """Gera certificados SSL para SAML"""
        try:
            # Verificar se openssl está disponível
            result = subprocess.run(['which', 'openssl'], capture_output=True, text=True)
            if result.returncode != 0:
                # Se openssl não estiver disponível, tentar instalar
                logger.warning("OpenSSL não encontrado, tentando instalar...")
                subprocess.run(['apt-get', 'update'], check=True)
                subprocess.run(['apt-get', 'install', '-y', 'openssl'], check=True)

            # Gerar chave privada
            cmd_key = [
                'openssl', 'genrsa', '-out', self.config.KEY_FILE, '2048'
            ]
            subprocess.run(cmd_key, check=True)

            # Gerar certificado autoassinado
            cmd_cert = [
                'openssl', 'req', '-new', '-x509', '-key', self.config.KEY_FILE,
                '-out', self.config.CERT_FILE, '-days', '365', '-nodes',
                '-subj', '/CN=AWS-SAML-IdP/O=Render Deployment/C=BR'
            ]
            subprocess.run(cmd_cert, check=True)

            # Proteger arquivos
            os.chmod(self.config.KEY_FILE, 0o600)
            os.chmod(self.config.CERT_FILE, 0o644)

            logger.info("Certificados gerados com sucesso!")

        except subprocess.CalledProcessError as e:
            logger.error(f"Erro ao gerar certificados: {e}")
            raise
        except Exception as e:
            logger.error(f"Erro inesperado ao gerar certificados: {e}")
            raise

def get_user_role(username):
    """
    Determina a role AWS baseado no usuário

    Args:
        username: Nome/email do usuário

    Returns:
        ARN da role ou None
    """
    config = Config()

    # Exemplo: mapeamento baseado em domínio de email
    if '@admin' in username or username.startswith('admin'):
        return config.ROLE_MAPPINGS.get('admin')
    elif '@dev' in username or username.startswith('dev'):
        return config.ROLE_MAPPINGS.get('developer')
    else:
        return config.ROLE_MAPPINGS.get('readonly')

def validate_user_credentials(username, password):
    """
    Valida credenciais do usuário

    Args:
        username: Nome/email do usuário
        password: Senha

    Returns:
        True se válido, False caso contrário
    """
    # IMPLEMENTAÇÃO DE EXEMPLO - Substitua com sua lógica real!
    # Exemplo 1: Banco de dados
    # Exemplo 2: Chamada a outro IdP (Microsoft Entra, Okta, etc.)
    # Exemplo 3: Autenticação simples para teste

    # Para teste: usuário=admin, senha=admin123
    valid_users = {
        'admin@empresa.com': {'password': 'admin123', 'role': 'admin'},
        'dev@empresa.com': {'password': 'dev123', 'role': 'developer'},
        'user@empresa.com': {'password': 'user123', 'role': 'readonly'}
    }

    user = valid_users.get(username)
    if user and user['password'] == password:
        return True
    return False

# Adicione esta função para inicializar o diretório de certificados
def init_cert_dir():
    if not os.path.exists(Config.CERT_DIR):
        os.makedirs(Config.CERT_DIR, exist_ok=True)
        print(f"Diretório de certificados criado: {Config.CERT_DIR}")
# E chame-a, por exemplo, no config.py ou aqui
init_cert_dir()
