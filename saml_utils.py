import base64
import uuid
import os
import subprocess
import logging
from datetime import datetime, timedelta, timezone
from lxml import etree
from signxml import XMLSigner
from config import Config
#teste

logger = logging.getLogger(__name__)

class samlResponseGenerator:
    """Gera SAML Response assinado para autenticação AWS"""

    def __init__(self):
        self.config = Config()
        Config.ensure_cert_dir_exists()

        # Verificar e gerar certificados se não existirem
        if not os.path.exists(self.config.CERT_FILE) or not os.path.exists(self.config.KEY_FILE):
            logger.info("Certificados não encontrados, gerando...")
            self._generate_certificates()

        # Carregar certificado e chave privada
        try:
            with open(self.config.CERT_FILE, 'rb') as f:
                self.certificate = f.read()

            with open(self.config.KEY_FILE, 'rb') as f:
                self.private_key = f.read()
        except Exception as e:
            logger.error(f"Erro ao carregar certificados: {e}")
            raise Exception("Certificados não encontrados e falha na geração.")

    def generate_saml_response(self, username, role_arn, session_name=None):
        """
        Gera um SAML 2.0 Response assinado e válido para AWS
        """
        if session_name is None:
            session_name = username

        assertion_id = f"_{uuid.uuid4()}"
        response_id = f"_{uuid.uuid4()}"
        
        # AWS exige UTC (Z)
        now = datetime.now(timezone.utc)
        issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        not_before = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        not_on_or_after = (now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Namespaces
        NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
        NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
        
        # Entity ID do IdP (deve bater com o console AWS)
        idp_entity_id = self.config.ENTITY_ID
        
        # Construir estrutura XML
        response = etree.Element(f"{{{NS_SAMLP}}}Response", 
                                ID=response_id, 
                                Version="2.0", 
                                IssueInstant=issue_instant,
                                Destination="https://signin.aws.amazon.com/saml",
                                nsmap={"samlp": NS_SAMLP, "saml": NS_SAML})
        
        issuer = etree.SubElement(response, f"{{{NS_SAML}}}Issuer")
        issuer.text = idp_entity_id
        
        status = etree.SubElement(response, f"{{{NS_SAMLP}}}Status")
        etree.SubElement(status, f"{{{NS_SAMLP}}}StatusCode", 
                         Value="urn:oasis:names:tc:SAML:2.0:status:Success")
        
        assertion = etree.SubElement(response, f"{{{NS_SAML}}}Assertion", 
                                   ID=assertion_id, 
                                   Version="2.0", 
                                   IssueInstant=issue_instant)
        
        ass_issuer = etree.SubElement(assertion, f"{{{NS_SAML}}}Issuer")
        ass_issuer.text = idp_entity_id
        
        # Subject
        subject = etree.SubElement(assertion, f"{{{NS_SAML}}}Subject")
        name_id = etree.SubElement(subject, f"{{{NS_SAML}}}NameID", 
                                 Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
        name_id.text = username
        
        subject_conf = etree.SubElement(subject, f"{{{NS_SAML}}}SubjectConfirmation", 
                                      Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
        etree.SubElement(subject_conf, f"{{{NS_SAML}}}SubjectConfirmationData", 
                        NotOnOrAfter=not_on_or_after, 
                        Recipient="https://signin.aws.amazon.com/saml")
        
        # Conditions
        conditions = etree.SubElement(assertion, f"{{{NS_SAML}}}Conditions", 
                                    NotBefore=not_before, 
                                    NotOnOrAfter=not_on_or_after)
        aud_rest = etree.SubElement(conditions, f"{{{NS_SAML}}}AudienceRestriction")
        audience = etree.SubElement(aud_rest, f"{{{NS_SAML}}}Audience")
        audience.text = "urn:amazon:webservices"
        
        # AuthnStatement
        authn_statement = etree.SubElement(assertion, f"{{{NS_SAML}}}AuthnStatement", 
                                         AuthnInstant=issue_instant, 
                                         SessionIndex=assertion_id)
        authn_context = etree.SubElement(authn_statement, f"{{{NS_SAML}}}AuthnContext")
        authn_class = etree.SubElement(authn_context, f"{{{NS_SAML}}}AuthnContextClassRef")
        authn_class.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
        
        # AttributeStatement (AWS Specific)
        attr_statement = etree.SubElement(assertion, f"{{{NS_SAML}}}AttributeStatement")
        
        # Role Attribute: arn:aws:iam::account:role/role-name,arn:aws:iam::account:saml-provider/provider-name
        principal_arn = f"arn:aws:iam::{self.config.AWS_ACCOUNT_ID}:saml-provider/{self.config.SAML_PROVIDER_NAME}"
        role_attr = etree.SubElement(attr_statement, f"{{{NS_SAML}}}Attribute", Name="https://aws.amazon.com/SAML/Attributes/Role")
        role_val = etree.SubElement(role_attr, f"{{{NS_SAML}}}AttributeValue")
        role_val.text = f"{role_arn},{principal_arn}"
        
        # RoleSessionName Attribute
        rsn_attr = etree.SubElement(attr_statement, f"{{{NS_SAML}}}Attribute", Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName")
        rsn_val = etree.SubElement(rsn_attr, f"{{{NS_SAML}}}AttributeValue")
        rsn_val.text = username
        
        # SessionDuration Attribute
        sd_attr = etree.SubElement(attr_statement, f"{{{NS_SAML}}}Attribute", Name="https://aws.amazon.com/SAML/Attributes/SessionDuration")
        sd_val = etree.SubElement(sd_attr, f"{{{NS_SAML}}}AttributeValue")
        sd_val.text = str(self.config.SAML_EXPIRATION_MINUTES * 60 * 12) # Ex: 1 hora

        # Assinar a asserção
        signer = XMLSigner()
        signed_assertion = signer.sign(assertion, key=self.private_key, cert=self.certificate)
        
        # Substituir a asserção não assinada pela assinada na resposta
        response.replace(assertion, signed_assertion)
        
        # Gerar XML final e codificar em Base64
        xml_str = etree.tostring(response, encoding="utf-8", xml_declaration=True)
        return base64.b64encode(xml_str).decode("utf-8")

    def _generate_certificates(self):
        """Gera certificados autoassinados se não existirem"""
        try:
            # Gerar chave privada
            cmd_key = ['openssl', 'genrsa', '-out', self.config.KEY_FILE, '2048']
            subprocess.run(cmd_key, check=True)

            # Gerar certificado
            cmd_cert = [
                'openssl', 'req', '-new', '-x509', '-key', self.config.KEY_FILE,
                '-out', self.config.CERT_FILE, '-days', '365', '-nodes',
                '-subj', '/CN=AWS-SAML-IdP/O=SAML-Project/C=BR'
            ]
            subprocess.run(cmd_cert, check=True)
            logger.info("Certificados gerados com sucesso.")
        except Exception as e:
            logger.error(f"Erro ao gerar certificados: {e}")
            raise

def get_user_role(username):
    config = Config()
    # Mapeamento simples
    if 'admin' in username or 'gujevinho' in username:
        return config.ROLE_MAPPINGS.get('admin')
    return config.ROLE_MAPPINGS.get('readonly')

def validate_user_credentials(username, password):
    # Credenciais de teste
    valid_users = {
        'admin@empresa.com': 'admin123',
        'gujevinho@gmail.com': 'Dev@281201'
    }
    return valid_users.get(username) == password
