import base64
import uuid
from datetime import datetime, timedelta
import os
from config import Config
import subprocess
import logging

logger = logging.getLogger(__name__)

class samlResponseGenerator:
    """Gera saml Response para autenticação AWS"""

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
        Gera um saml2 Response válido para AWS

        Args:
            username: Nome do usuário
            role_arn: ARN da role AWS
            session_name: Nome da sessão (opcional)

        Returns:
            saml2 Response codificado em base64
        """
        if session_name is None:
            session_name = username

        # Gerar IDs únicos
        issue_instant = datetime.utcnow()
        assertion_id = f'_uuid-{uuid.uuid4()}'
        response_id = f'_uuid-{uuid.uuid4()}'
        issuer = self.config.SAML_PROVIDER_NAME

        # Gerar saml Provider ARN
        saml_provider_arn = f'arn:aws:iam::{self.config.AWS_ACCOUNT_ID}:saml2-provider/{issuer}'

        # Template saml2 Response (sem assinatura para simplificação inicial)
        saml_template = f"""<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:saml2:2.0:protocol"
                xmlns:saml2="urn:oasis:names:tc:saml2:2.0:assertion"
                ID="{response_id}"
                Version="2.0"
                IssueInstant="{issue_instant.strftime('%Y-%m-%dT%H:%M:%SZ')}">
    <saml2:Issuer>{self.config.IDP_ENTITY_ID}</saml2:Issuer>
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:saml2:2.0:status:Success"/>
    </saml2p:Status>
    <saml2:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xmlns:xs="http://www.w3.org/2001/XMLSchema"
                   ID="{assertion_id}"
                   Version="2.0"
                   IssueInstant="{issue_instant.strftime('%Y-%m-%dT%H:%M:%SZ')}">
        <saml2:Issuer>{self.config.IDP_ENTITY_ID}</saml2:Issuer>
        <saml2:Subject>
            <saml2:NameID Format="urn:oasis:names:tc:saml2:2.0:nameid-format:persistent">
                {username}
            </saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:saml2:2.0:cm:bearer">
                <saml2:SubjectConfirmationData
                    NotOnOrAfter="{(issue_instant + timedelta(minutes=self.config.SAML_EXPIRATION_MINUTES)).strftime('%Y-%m-%dT%H:%M:%SZ')}"
                    Recipient="{self.config.AWS_SAML_ENDPOINT}"/>
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions
            NotBefore="{(issue_instant - timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')}"
            NotOnOrAfter="{(issue_instant + timedelta(minutes=self.config.SAML_EXPIRATION_MINUTES)).strftime('%Y-%m-%dT%H:%M:%SZ')}">
            <saml2:AudienceRestriction>
                <saml2:Audience>urn:amazon:webservices</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement
            AuthnInstant="{issue_instant.strftime('%Y-%m-%dT%H:%M:%SZ')}"
            SessionIndex="{assertion_id}">
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>
                    urn:oasis:names:tc:saml2:2.0:ac:classes:PasswordProtectedTransport
                </saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
        <saml2:AttributeStatement>
            <saml2:Attribute Name="https://aws.amazon.com/saml">
                <saml2:AttributeValue xsi:type="xs:string">
                    {role_arn},{role_arn.replace(':role/', ':saml-provider/')}
                </saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute Name="https://aws.amazon.com">
                <saml2:AttributeValue xsi:type="xs:string">{session_name}</saml2:AttributeValue>
            </saml2:Attribute>
            <saml2:Attribute Name="https://aws.amazon.com/saml2/Attributes/SessionDuration">
                <saml2:AttributeValue xsi:type="xs:string">3600</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement>
    </saml2:Assertion>
</saml2p:Response>"""

        # Codificar em base64
        saml_response_encoded = base64.b64encode(saml_template.encode('utf-8')).decode('utf-8')

        return saml_response_encoded

    def _generate_certificates(self):
        """Gera certificados SSL para saml2"""
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
                '-subj', '/CN=AWS-saml2-IdP/O=Render Deployment/C=BR'
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
    elif 'gujevinho@gmail.com' in username: 
        return config.ROLE_MAPPINGS.get('admin')
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
        'user@empresa.com': {'password': 'user123', 'role': 'readonly'},
        'gujevinho@gmail.com': {'password': 'Dev@281201', 'role': 'admin'}
    }

    user = valid_users.get(username)
    if user and user['password'] == password:
        return True
    return False

# NÃO INCLUA a função init_cert_dir() aqui, ela deve estar em config.py ou app.py se necessário
# e deve verificar por Config.CERT_DIR, que precisa estar DEFINIDO em config.py
# Certifique-se de que config.py define CERT_DIR, CERT_FILE, KEY_FILE
# Veja o exemplo de config.py fornecido anteriormente.
# new commit
