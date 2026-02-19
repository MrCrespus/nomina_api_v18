# -*- coding: utf-8 -*-
import base64
import logging
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, pkcs12
import hashlib
from copy import deepcopy

# --- XML Utils (Ported from l10n_co_dian/xml_utils.py) ---
NS_MAP = {'ds': "http://www.w3.org/2000/09/xmldsig#"}


def _canonicalize_node(node, **kwargs):
    return etree.tostring(node, method="c14n", with_comments=False, **kwargs)


def _get_uri(uri, reference, base_uri=""):
    transform_nodes = reference.findall(".//{*}Transform")
    exc_c14n = bool(transform_nodes) and transform_nodes[0].attrib.get(
        'Algorithm') == 'http://www.w3.org/2001/10/xml-exc-c14n#'
    prefix_list = []
    if exc_c14n:
        inclusive_ns_node = transform_nodes[0].find(
            ".//{*}InclusiveNamespaces")
        if inclusive_ns_node is not None and inclusive_ns_node.attrib.get('PrefixList'):
            prefix_list = inclusive_ns_node.attrib.get('PrefixList').split(' ')

    node = deepcopy(reference.getroottree().getroot())
    if uri == base_uri:
        for signature in node.findall('.//ds:Signature', namespaces=NS_MAP):
            if signature.tail:
                if (previous := signature.getprevious()) is not None:
                    previous.tail = "".join(
                        [previous.tail or "", signature.tail or ""])
                else:
                    signature.getparent().text = "".join(
                        [signature.getparent().text or "", signature.tail or ""])
            signature.getparent().remove(signature)
        return _canonicalize_node(node, exclusive=exc_c14n, inclusive_ns_prefixes=prefix_list)

    if uri.startswith("#"):
        path = "//*[@*[local-name() = '{}' ]=$uri]"
        results = node.xpath(path.format("Id"), uri=uri.lstrip("#"))
        if len(results) == 1:
            return _canonicalize_node(results[0], exclusive=exc_c14n, inclusive_ns_prefixes=prefix_list)
        if len(results) > 1:
            raise Exception(
                f"Ambiguous reference URI {uri} resolved to {len(results)} nodes")

    raise Exception(f'URI {uri} not found')


def _reference_digests(node, base_uri=""):
    for reference in node.findall("ds:Reference", namespaces=NS_MAP):
        ref_node = _get_uri(reference.get("URI", ""),
                            reference, base_uri=base_uri)
        lib = hashlib.new("sha256", ref_node)
        reference.find("ds:DigestValue",
                       namespaces=NS_MAP).text = base64.b64encode(lib.digest())


def _sign_cms(content, certificate_data, password):
    # This is a simplification of certificate._sign logic for this context
    # We need to sign the content using the private key from the PKCS12
    try:
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            certificate_data, password.encode() if password else None
        )
    except Exception as e:
        # Try loading as PEM if PKCS12 fails (though usually it is PKCS12)
        # For this specific task, we assume PKCS12 as standard in Odoo for this.
        raise Exception(f"Failed to load certificate: {e}")

    # Sign
    from cryptography.hazmat.primitives.asymmetric import padding
    signature = private_key.sign(
        content,
        # Wait, we need to check if it's PKCS1 v1.5
        padding.PKCS1(hashes.SHA256())
    )
    # The default padding in standard XMLDSig with RSA-SHA256 is usually PKCS1v15
    # Let's verify algorithm. Odoo uses `certificate._sign` which calls `self._get_key().sign(data, padding.PKCS1v15(), getattr(hashes, hashing_algorithm.upper())())`
    # We will replicate that.
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

    signature = private_key.sign(
        content,
        asym_padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature)


def _fill_signature(node, private_key, certificate_chain):
    signed_info_xml = node.find("ds:SignedInfo", namespaces=NS_MAP)
    exc_c14n = signed_info_xml.find(".//{*}CanonicalizationMethod").attrib.get(
        'Algorithm') == 'http://www.w3.org/2001/10/xml-exc-c14n#'
    prefix_list = []
    if exc_c14n:
        inclusive_ns_node = signed_info_xml.find(
            ".//{*}CanonicalizationMethod").find(".//{*}InclusiveNamespaces")
        if inclusive_ns_node is not None and inclusive_ns_node.attrib.get('PrefixList'):
            prefix_list = inclusive_ns_node.attrib.get('PrefixList').split(' ')

    canonical_si = _canonicalize_node(
        signed_info_xml, exclusive=exc_c14n, inclusive_ns_prefixes=prefix_list)

    # Sign logic
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    signature = private_key.sign(
        canonical_si,
        asym_padding.PKCS1v15(),
        hashes.SHA256()
    )
    node.find("ds:SignatureValue", namespaces=NS_MAP).text = base64.b64encode(
        signature).decode()


def _remove_tail_and_text_in_hierarchy(node):
    node.tail = None
    if list(node):
        node.text = None
        for child in node:
            _remove_tail_and_text_in_hierarchy(child)


class SignatureService:
    def __init__(self):
        pass

    def sign(self, xml_content, cert_content_b64, cert_password):
        """
        Signs the XML content using the provided certificate (PKCS12 base64).
        """
        try:
            cert_data_bytes = base64.b64decode(cert_content_b64)
            print(
                f"      [Signer DEBUG] PKCS12 Bytes Head: {cert_data_bytes[:20]}")

            # CHECK: Is it actually a PEM file?
            if cert_data_bytes.strip().startswith(b'-----'):
                print(
                    f"      [Signer DEBUG] El contenido NO es PKCS12, es PEM. Cambiando estrategia...")
                # Recode to base64 for sign_with_pem (it expects b64 strings)
                # We pass the same content for both key and cert, assuming it's a bundle
                return self.sign_with_pem(
                    xml_content,
                    cert_content_b64,
                    cert_content_b64,
                    cert_password
                )

            # Load PKCS12
            private_key, main_cert, additional_certs = pkcs12.load_key_and_certificates(
                cert_data_bytes, cert_password.encode() if cert_password else None
            )
            cert_chain = [main_cert] + \
                (additional_certs if additional_certs else [])

        except Exception as e:
            raise Exception(f"Failed to load as PKCS12 with password: {e}")

        return self._build_signature_structure(xml_content, private_key, cert_chain)

    def sign_with_pem(self, xml_content, private_key_pem_b64, public_key_pem_b64=None, password=None):
        """
        Signs the XML content using provided PEM keys (Base64 encoded).
        If public_key_pem_b64 is None, tries to find certificate in private_key_pem_b64.
        """
        try:
            # Decode Base64 PEMs
            private_key_bytes = base64.b64decode(private_key_pem_b64)
            public_key_bytes = base64.b64decode(
                public_key_pem_b64) if public_key_pem_b64 else private_key_bytes

            # Debug: Inspect header
            print(
                f"      [Signer DEBUG] Private Key Bytes Head: {private_key_bytes[:20]}")

            # Validate PEM Header
            if not private_key_bytes.strip().startswith(b'-----'):
                raise ValueError(
                    "Content does not look like a PEM file (missing '-----BEGIN'). It might be an image or binary.")

            # Load Private Key
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            try:
                private_key = load_pem_private_key(
                    private_key_bytes,
                    password=password.encode() if password else None
                )
            except TypeError as e:
                # Handle "Password was given but private key is not encrypted"
                if "not encrypted" in str(e):
                    print(
                        f"      [Signer DEBUG] La llave no está encriptada pero se proporcionó contraseña. Reintentando sin contraseña...")
                    private_key = load_pem_private_key(
                        private_key_bytes, password=None)
                else:
                    raise e
            except ValueError as e:
                # Depending on version it might be ValueError
                if "not encrypted" in str(e):
                    print(
                        f"      [Signer DEBUG] La llave no está encriptada pero se proporcionó contraseña. Reintentando sin contraseña...")
                    private_key = load_pem_private_key(
                        private_key_bytes, password=None)
                else:
                    raise e
            except Exception as e:
                if "not encrypted" in str(e):
                    print(
                        f"      [Signer DEBUG] La llave no está encriptada pero se proporcionó contraseña. Reintentando sin contraseña...")
                    private_key = load_pem_private_key(
                        private_key_bytes, password=None)
                else:
                    raise e

            # Load Public Key / Certificate
            cert_chain = []

            # 1. Try finding X509 certificates in the bytes
            try:
                # x509.load_pem_x509_certificates requires cryptography >= 38.0?
                # Or we can iterate if multiple. 'load_pem_x509_certificates' loads all?
                # No, standard is load_pem_x509_certificate (singular).
                # We can try to split by "-----BEGIN CERTIFICATE-----" if multiple.

                # Check directly if we can load one
                try:
                    cert = x509.load_pem_x509_certificate(public_key_bytes)
                    cert_chain = [cert]
                except ValueError:
                    # Maybe it has multiple or extra data (like key components) before the cert
                    # Simple parser for multiple certs:
                    import re
                    pem_str = public_key_bytes.decode('utf-8', errors='ignore')
                    certs_found = re.findall(
                        r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem_str, re.DOTALL)
                    for c_str in certs_found:
                        cert_chain.append(
                            x509.load_pem_x509_certificate(c_str.encode('utf-8')))

                if not cert_chain:
                    raise Exception(
                        "No certificates found in provided PEM data.")

            except Exception as e:
                # Fallback: maybe the user provided just a public key? (Not useful for XAdES which needs IssuerSerial)
                raise Exception(
                    f"Could not extract X509 certificate from provided PEM: {e}")

        except Exception as e:
            raise Exception(f"Error loading PEM keys: {e}")

        # Reuse the XML building logic
        return self._build_signature_structure(xml_content, private_key, cert_chain)

    def _build_signature_structure(self, xml_content, private_key, cert_chain):
        if not cert_chain:
            raise ValueError("Certificate chain is empty")
        main_cert = cert_chain[0]

        # 2. Parse XML
        root = etree.fromstring(xml_content.encode('utf-8'))

        nsmap = {k: v for k, v in root.nsmap.items() if k}
        nsmap.setdefault('ds', 'http://www.w3.org/2000/09/xmldsig#')
        nsmap.setdefault('xades', 'http://uri.etsi.org/01903/v1.3.2#')

        # 3. Prepare Signature Structure (Template)
        # In Odoo, this is a qweb template. Here we construct it programmatically or string template.
        # We need the signature node to be appended to UBLExtensions.

        # Check if UBLExtensions exists, if not create (though mapper should have it ideally, or we create)
        ubl_extensions = root.find('.//{*}UBLExtensions')
        if ubl_extensions is None:
            # Basic UBL structure expects it at top
            ubl_extensions = etree.Element("ext:UBLExtensions", nsmap={
                                           'ext': "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2"})
            root.insert(0, ubl_extensions)

        # Create Signature Extension
        # We need a unique ID for the signature
        import datetime
        unique_id = f"Signature-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        key_info_id = f"{unique_id}-KeyInfo"
        signed_props_id = f"xmldsig-{unique_id}-signedprops"

        # Simplified Signature Construction (since I don't have the template file handy on disk)
        # I will construct the etree elements manually to mimic "l10n_co_radian_events.ubl_extension_dian_events"

        ubl_extension = etree.SubElement(
            ubl_extensions, "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}UBLExtension")
        ext_content = etree.SubElement(
            ubl_extension, "{urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2}ExtensionContent")

        signature = etree.SubElement(
            ext_content, "{http://www.w3.org/2000/09/xmldsig#}Signature", Id=unique_id)

        signed_info = etree.SubElement(
            signature, "{http://www.w3.org/2000/09/xmldsig#}SignedInfo")

        # Canonicalization
        etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod",
                         Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")

        # Signature Method
        etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}SignatureMethod",
                         Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

        # References
        # 1. Document Reference (Empty URI)
        ref_doc = etree.SubElement(
            signed_info, "{http://www.w3.org/2000/09/xmldsig#}Reference", URI="")
        transforms = etree.SubElement(
            ref_doc, "{http://www.w3.org/2000/09/xmldsig#}Transforms")
        etree.SubElement(transforms, "{http://www.w3.org/2000/09/xmldsig#}Transform",
                         Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
        etree.SubElement(ref_doc, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
                         Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
        # To be filled
        etree.SubElement(
            ref_doc, "{http://www.w3.org/2000/09/xmldsig#}DigestValue")

        # 2. KeyInfo Reference
        ref_key = etree.SubElement(
            signed_info, "{http://www.w3.org/2000/09/xmldsig#}Reference", URI=f"#{key_info_id}")
        etree.SubElement(ref_key, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
                         Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
        # To be filled
        etree.SubElement(
            ref_key, "{http://www.w3.org/2000/09/xmldsig#}DigestValue")

        # 3. SignedProperties Reference
        ref_props = etree.SubElement(
            signed_info, "{http://www.w3.org/2000/09/xmldsig#}Reference", URI=f"#{signed_props_id}")
        etree.SubElement(ref_props, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
                         Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
        # To be filled
        etree.SubElement(
            ref_props, "{http://www.w3.org/2000/09/xmldsig#}DigestValue")

        # SignatureValue
        etree.SubElement(
            signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue")

        # KeyInfo
        key_info = etree.SubElement(
            signature, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo", Id=key_info_id)
        x509_data = etree.SubElement(
            key_info, "{http://www.w3.org/2000/09/xmldsig#}X509Data")
        x509_cert = etree.SubElement(
            x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
        # Fill Cert Base64
        cert_b64 = base64.b64encode(main_cert.public_bytes(
            Encoding.PEM)).decode().replace('\n', '')
        # Remove headers/footers if PEM
        cert_b64 = cert_b64.replace(
            "-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
        x509_cert.text = cert_b64

        # Object -> QualifyingProperties
        object_node = etree.SubElement(
            signature, "{http://www.w3.org/2000/09/xmldsig#}Object")
        qualifying_props = etree.SubElement(
            object_node, "{http://uri.etsi.org/01903/v1.3.2#}QualifyingProperties", Target=f"#{unique_id}")

        signed_props = etree.SubElement(
            qualifying_props, "{http://uri.etsi.org/01903/v1.3.2#}SignedProperties", Id=signed_props_id)
        signed_sig_props = etree.SubElement(
            signed_props, "{http://uri.etsi.org/01903/v1.3.2#}SignedSignatureProperties")

        # SigningTime
        signing_time = etree.SubElement(
            signed_sig_props, "{http://uri.etsi.org/01903/v1.3.2#}SigningTime")
        signing_time.text = datetime.datetime.utcnow().strftime(
            '%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

        # SigningCertificate
        signing_cert = etree.SubElement(
            signed_sig_props, "{http://uri.etsi.org/01903/v1.3.2#}SigningCertificate")

        # Add Logic for Chain but mostly just main cert for brevity or robust full chain loop
        for cert_item in cert_chain:
            cert = etree.SubElement(
                signing_cert, "{http://uri.etsi.org/01903/v1.3.2#}Cert")
            cert_digest = etree.SubElement(
                cert, "{http://uri.etsi.org/01903/v1.3.2#}CertDigest")
            etree.SubElement(cert_digest, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
                             Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")

            digest_val = base64.b64encode(
                cert_item.fingerprint(hashes.SHA256())).decode()
            etree.SubElement(
                cert_digest, "{http://www.w3.org/2000/09/xmldsig#}DigestValue").text = digest_val

            issuer_serial = etree.SubElement(
                cert, "{http://uri.etsi.org/01903/v1.3.2#}IssuerSerial")
            etree.SubElement(
                issuer_serial, "{http://www.w3.org/2000/09/xmldsig#}X509IssuerName").text = cert_item.issuer.rfc4514_string()
            etree.SubElement(
                issuer_serial, "{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber").text = str(cert_item.serial_number)

        # SignedDataObjectProperties (Optional but usually present in Radian)
        # signed_data_props = etree.SubElement(signed_props, "{http://uri.etsi.org/01903/v1.3.2#}SignedDataObjectProperties")
        # ...

        # 4. Cleanup and Reference Digests
        _remove_tail_and_text_in_hierarchy(root)
        _reference_digests(signed_info)

        # 5. Fill Signature
        _fill_signature(signature, private_key, cert_chain)

        return etree.tostring(root, encoding='utf-8', xml_declaration=True, pretty_print=False).decode()
