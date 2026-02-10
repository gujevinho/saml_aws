import os
from datetime import datetime, timedelta

#from saml_utils import init_cert_dir

class Config:
    # Chave secreta do Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'sua-chave-secreta-aqui')
    
    # Configurações SAML IdP
    IDP_ENTITY_ID = 'urn:amazon:webservices'
    IDP_NAME = 'AWS-SAML-IdP'
    ENTITY_ID = 'https://dev-api.facesign.in/api/saml/metadata/5f273bdd-d8c5-4de3-80f1-2c715fae05d0'
    
    # Certificado e chave (gerar com OpenSSL)
    CERT_DIR = os.path.join(os.path.dirname(__file__), 'static', 'cert')
    CERT_FILE = os.path.join(os.path.dirname(__file__), 'static', 'cert', 'idp.cer')
    KEY_FILE = os.path.join(os.path.dirname(__file__), 'static', 'cert', 'idp.key')
    
    # AWS SAML Endpoint
    AWS_SAML_ENDPOINT = 'https://signin.aws.amazon.com/saml/acs/SAMLSPH4D4VUKVI56COEHT'
    #AWS_SAML_ENDPOINT = 'https://signin.aws.amazon.com/saml'
    #AWS_SAML_ENDPOINT = 'https://signin.aws.amazon.com/saml/acs'
    
    # ARNs das roles AWS (configurar no IAM)
    #AWS_ACCOUNT_ID = '058264482789'  # Substitua pelo seu account ID
    #SAML_PROVIDER_NAME = 'Face'  # Nome do SAML Provider no IAM

        # ARNs das roles AWS (configurar no IAM)
    AWS_ACCOUNT_ID = os.environ.get('AWS_ACCOUNT_ID', '058264482789')
    SAML_PROVIDER_NAME = os.environ.get('SAML_PROVIDER_NAME', 'Face')
    
    # Mapeamento de usuários para roles
    ROLE_MAPPINGS = {
        'admin': f'arn:aws:iam::{AWS_ACCOUNT_ID}:role/Face',
        'readonly': f'arn:aws:iam::{AWS_ACCOUNT_ID}:role/Face',
        'developer': f'arn:aws:iam::{AWS_ACCOUNT_ID}:role/Face'
    }

    ROLE2_MAPPINGS = {
        'admin': f'arn:aws:iam::{AWS_ACCOUNT_ID}:saml-provider/Face',
        'readonly': f'arn:aws:iam::{AWS_ACCOUNT_ID}::saml-provider/Face',
        'developer': f'arn:aws:iam::{AWS_ACCOUNT_ID}::saml-provider/Face'
    }
    
    # URL base da aplicação
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')
    
    # Tempo de expiração do SAML Assertion (minutos)
    SAML_EXPIRATION_MINUTES = 5
    
    # RelayState (URL de destino após login na AWS)
    RELAY_STATE = 'https://signin.aws.amazon.com/saml'

        # Verificar se diretório de certificados existe (função utilitária)
    @staticmethod
    def ensure_cert_dir_exists():
        if not os.path.exists(Config.CERT_DIR):
            os.makedirs(Config.CERT_DIR, exist_ok=True)
            print(f"Diretório de certificados criado: {Config.CERT_DIR}")

# E chame-a, por exemplo, no config.py ou aqui
 #   init_cert_dir() 