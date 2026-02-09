import base64
import uuid
from datetime import datetime, timedelta, timezone
from lxml import etree
from signxml import XMLSigner

class SAMLResponseGenerator:
    def __init__(self, cert_path, key_path, entity_id):
        self.cert_path = cert_path
        self.key_path = key_path
        self.entity_id = entity_id # Ex: "https://meuidp.com.br/metadata"
        
        with open(cert_path, "rb") as f:
            self.cert = f.read()
        with open(key_path, "rb") as f:
            self.key = f.read()

    def generate_response(self, username, role_arn, principal_arn, session_duration=3600):
        assertion_id = f"_{uuid.uuid4()}"
        response_id = f"_{uuid.uuid4()}"
        now = datetime.now(timezone.utc)
        issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        not_before = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        not_on_or_after = (now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Namespaces
        NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
        NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
        NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
        NS_XS = "http://www.w3.org/2001/XMLSchema"
        
        # Build XML structure
        response = etree.Element(f"{{{NS_SAMLP}}}Response", 
                                ID=response_id, 
                                Version="2.0", 
                                IssueInstant=issue_instant,
                                nsmap={"samlp": NS_SAMLP, "saml": NS_SAML})
        
        issuer = etree.SubElement(response, f"{{{NS_SAML}}}Issuer")
        issuer.text = self.entity_id
        
        status = etree.SubElement(response, f"{{{NS_SAMLP}}}Status")
        status_code = etree.SubElement(status, f"{{{NS_SAMLP}}}StatusCode", 
                                     Value="urn:oasis:names:tc:SAML:2.0:status:Success")
        
        assertion = etree.SubElement(response, f"{{{NS_SAML}}}Assertion", 
                                   ID=assertion_id, 
                                   Version="2.0", 
                                   IssueInstant=issue_instant)
        
        ass_issuer = etree.SubElement(assertion, f"{{{NS_SAML}}}Issuer")
        ass_issuer.text = self.entity_id
        
        # Subject
        subject = etree.SubElement(assertion, f"{{{NS_SAML}}}Subject")
        name_id = etree.SubElement(subject, f"{{{NS_SAML}}}NameID", 
                                 Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
        name_id.text = username
        
        subject_conf = etree.SubElement(subject, f"{{{NS_SAML}}}SubjectConfirmation", 
                                      Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
        subject_conf_data = etree.SubElement(subject_conf, f"{{{NS_SAML}}}SubjectConfirmationData", 
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
        
        # Role Attribute
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
        sd_val.text = str(session_duration)
        
        # Sign the assertion
        signer = XMLSigner()
        signed_assertion = signer.sign(assertion, key=self.key, cert=self.cert)
        
        # Replace the unsigned assertion with the signed one in the response
        response.replace(assertion, signed_assertion)
        
        # Final XML
        xml_str = etree.tostring(response, encoding="utf-8", xml_declaration=True)
        return base64.b64encode(xml_str).decode("utf-8")
