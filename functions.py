# For cert gen
from datetime import timedelta
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.http import JsonResponse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from datetime import datetime
import os
import base64

def generate_client_cert(unit_uuid, unit_type):

    # Cert details
    common_name = str("{}_{}".format(unit_type, unit_uuid).lower())
    organization_name = "K-Tech International, Inc."
    organization_unit_name = "Software Engineering Department"
    postal_address_oid = "56 Ella Grasso Avenue"
    locality_name = "Torrington"
    state_or_province_name = "CT"
    postal_code_oid = "06790"
    country_name = "US"
    dns_name = "connect.ktechonline.com"

    # Load intermediate CA cert and key from env vars
    ca_cert = os.getenv("INTERMEDIATE_CA_CRT_PEM").replace('\\n', '\n')
    ca_key = os.getenv("INTERMEDIATE_CA_KEY_PEM").replace('\\n', '\n')

    ca_cert = x509.load_pem_x509_certificate(
        ca_cert.encode('utf-8')
    )
    ca_key = serialization.load_pem_private_key(
        ca_key.encode('utf-8'),
        password=None
    )

    # Generate client private key
    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Declare Additional Cert Details
    POSTAL_ADDRESS_OID = ObjectIdentifier("2.5.4.9")
    POSTAL_CODE_OID = ObjectIdentifier("2.5.4.17")

    # Build certificate subject with uuid and type
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit_name),
        x509.NameAttribute(POSTAL_ADDRESS_OID, postal_address_oid),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(POSTAL_CODE_OID, postal_code_oid),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
    ])

    # Create and sign certificate
    cert = x509.CertificateBuilder(
    ).subject_name(
        subject
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(dns_name),
        ]),
        critical=False,
    ).issuer_name(
        ca_cert.issuer
    ).public_key(
        client_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        # Valid from now
        datetime.utcnow()
    ).not_valid_after(
        # Valid for 30 years
        datetime.utcnow() + timedelta(days=365*30)
    ).sign(ca_key, hashes.SHA256())

    # Encode to PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Returns as bytes
    return cert_pem, key_pem


def load_intermediate_ca():
    """Load intermediate CA certificate"""

    ca_cert = os.getenv("INTERMEDIATE_CA_CRT_PEM").replace('\\n', '\n')

    return x509.load_pem_x509_certificate(
        ca_cert.encode('utf-8'),
        default_backend()
    )


# Load your CA certificates (do this once at startup, not in view)
def load_ca_certs():
    """Load intermediate CA certificate"""

    # Get intermediate CA from environment or file
    intermediate_ca_pem = os.getenv("INTERMEDIATE_CA_CRT_PEM").replace('\\n', '\n')

    try:
        intermediate_ca = x509.load_pem_x509_certificate(
            intermediate_ca_pem.encode('utf-8'),
            default_backend()
        )
    except ValueError as e:
        raise ValueError(f'Invalid intermediate CA certificate: {str(e)}')

    return intermediate_ca


# Load once at module level
INTERMEDIATE_CA = None
INTERMEDIATE_CA_ERROR = None


def get_intermediate_ca():
    """Get intermediate CA certificate (cached)"""
    global INTERMEDIATE_CA, INTERMEDIATE_CA_ERROR

    if INTERMEDIATE_CA is not None:
        return INTERMEDIATE_CA

    if INTERMEDIATE_CA_ERROR is not None:
        raise INTERMEDIATE_CA_ERROR

    try:
        INTERMEDIATE_CA = load_ca_certs()
        return INTERMEDIATE_CA
    except (FileNotFoundError, ValueError) as e:
        INTERMEDIATE_CA_ERROR = e
        raise


def validate_client_cert(request):

    cert_header = request.META.get('HTTP_X_CLIENT_CERTIFICATE')

    if not cert_header:
        return JsonResponse(
            {'error': 'No certificate provided in X-Client-Certificate header'},
            status=400
        )
    # Decode from base64
    try:
        cert_pem = base64.b64decode(cert_header).decode('utf-8')
    except Exception as e:
        return JsonResponse({'error': f'Invalid base64 encoding: {str(e)}'}, status=400)

    try:
        # Load client certificate
        client_cert = x509.load_pem_x509_certificate(
            cert_pem.encode('utf-8'),
            default_backend()
        )

        # Get intermediate CA
        try:
            intermediate_ca = get_intermediate_ca()
        except FileNotFoundError as e:
            return JsonResponse(
                {'error': str(e)},
                status=500
            )
        except ValueError as e:
            return JsonResponse(
                {'error': str(e)},
                status=500
            )

        # ===== VERIFY CERTIFICATE CHAIN =====
        # Verify client certificate was signed by intermediate CA
        try:
            # Verify signature using intermediate CA's public key
            intermediate_ca.public_key().verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except InvalidSignature:
            return JsonResponse(
                {'error': 'Certificate NOT signed by intermediate CA'},
                status=403
            )
        except ValueError as e:
            return JsonResponse(
                {'error': f'Certificate verification failed: {str(e)}'},
                status=403
            )

        # ===== CHECK EXPIRATION =====
        time_now = datetime.utcnow()

        if client_cert.not_valid_before > time_now:
            return JsonResponse(
                {'error': f'Certificate not valid yet. Valid from: {client_cert.not_valid_before}'},
                status=400
            )

        if client_cert.not_valid_after < time_now:
            return JsonResponse(
                {'error': f'Certificate expired on: {client_cert.not_valid_after}'},
                status=400
            )

        # ===== CERTIFICATE IS VALID =====
        return JsonResponse({
            'status': 'success',
            'message': 'Certificate is valid and signed by intermediate CA',
            'subject': client_cert.subject.rfc4514_string(),
            'issuer': client_cert.issuer.rfc4514_string(),
            'serial': str(client_cert.serial_number),
            'valid_from': client_cert.not_valid_before.isoformat(),
            'valid_until': client_cert.not_valid_after.isoformat(),
        }, status=200)

    except (OSError, IOError) as e:
        return JsonResponse(
            {'error': f'Failed to load CA certificate: {str(e)}'},
            status=500
        )

    except ValueError as e:
        return JsonResponse(
            {'error': f'Certificate validation error: {str(e)}'},
            status=400
        )
