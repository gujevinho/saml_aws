# SAML AWS Integration

Aplicação Flask que funciona como um Identity Provider (IdP) SAML para integração com AWS.

## Requisitos

- Python 3.11+
- pip

## Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/saml_aws.git
cd saml_aws
```

2. Crie um ambiente virtual:
```bash
python -m venv venv
source venv/bin/activate  # No Windows: venv\Scripts\activate
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

4. Configure as variáveis de ambiente:
```bash
cp .env.example .env
# Edite .env com suas configurações
```

5. Gere os certificados SAML:
```bash
openssl req -x509 -newkey rsa:2048 -keyout static/cert/idp.key -out static/cert/idp.crt -days 365 -nodes
```

6. Execute a aplicação:
```bash
python app.py
```

## Deployment no Render

1. Push seu código para GitHub
2. Acesse [render.com](https://render.com)
3. Crie um novo Web Service
4. Conecte seu repositório GitHub
5. Configure:
   - **Runtime**: Python 3.11
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
6. Adicione as variáveis de ambiente (Environment Variables)
7. Deploy!

## Variáveis de Ambiente Necessárias

- `SECRET_KEY`: Chave secreta para sessões Flask
- `AWS_ACCOUNT_ID`: ID da conta AWS
- `SAML_PROVIDER_NAME`: Nome do provider SAML no AWS IAM

## Estrutura

```
saml_aws/
├── app.py              # Aplicação Flask
├── config.py           # Configurações
├── saml_utils.py       # Utilitários SAML
├── requirements.txt    # Dependências Python
├── runtime.txt         # Versão Python
├── Procfile            # Configuração para Heroku/Render
├── static/
│   └── cert/          # Certificados SAML
├── templates/
│   ├── login.html
│   ├── dashboard.html
│   └── saml_post.html
└── README.md
```

## Segurança

⚠️ **Importante**: 
- Nunca commit os arquivos de certificado/chave SAML (`static/cert/*.key`, `static/cert/*.crt`)
- Use variáveis de ambiente para dados sensíveis
- Altere a `SECRET_KEY` em produção
- Configure HTTPS obrigatório em produção

## Suporte

Para mais informações, consulte a documentação:
- [Flask](https://flask.palletsprojects.com/)
- [python3-saml](https://github.com/onelogin/python3-saml)
- [AWS SAML Integration](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html)
