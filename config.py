import os
from datetime import datetime, timedelta

class Config:
    # Chave secreta do Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'sua-chave-secreta-aqui')
    
    # Configurações SAML IdP
    IDP_ENTITY_ID = 'arn:aws:iam::058264482789:role/Face_aws'
    IDP_NAME = 'AWS-SAML-IdP'
    
    # Certificado e chave (gerar com OpenSSL)
    CERT_FILE = os.path.join(os.path.dirname(__file__), 'static', 'cert', 'idp.crt')
    KEY_FILE = os.path.join(os.path.dirname(__file__), 'static', 'cert', 'idp.key')
    
    # AWS SAML Endpoint
    AWS_SAML_ENDPOINT = 'https://signin.aws.amazon.com/saml/acs/SAMLSPH4D4VUKVI56COEHT'
    
    # ARNs das roles AWS (configurar no IAM)
    AWS_ACCOUNT_ID = '123456789012'  # Substitua pelo seu account ID
    SAML_PROVIDER_NAME = 'MeuSAMLProvider'  # Nome do SAML Provider no IAM
    
    # Mapeamento de usuários para roles
    ROLE_MAPPINGS = {
        'admin': f'arn:aws:iam::058264482789:role/Face_aws',
        'readonly': f'arn:aws:iam::{AWS_ACCOUNT_ID}:role/AWS-ReadOnlyRole',
        'developer': f'arn:aws:iam::{AWS_ACCOUNT_ID}:role/AWS-DeveloperRole'
    }
    
    # URL base da aplicação
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')
    
    # Tempo de expiração do SAML Assertion (minutos)
    SAML_EXPIRATION_MINUTES = 5
    
    # RelayState (URL de destino após login na AWS)
    RELAY_STATE = 'https://signin.aws.amazon.com/saml/acs/SAMLSPH4D4VUKVI56COEHT'