import json
import base64
from django.http import JsonResponse
from .functions import generate_client_cert, validate_client_cert

def cert_gen(request, unit_type, qty):

    unit_uuid = "ABC123"
    unit_type = unit_type

    cert_pem, key_pem = generate_client_cert(unit_uuid, unit_type)

    # Replace with actual new lines
    print(cert_pem.decode('utf-8').replace('\\n', '\n'))

    return JsonResponse({
        "cert_str": cert_pem.decode('utf-8'),  # Stringify
        "key_str": key_pem.decode('utf-8'),  # Stringify
        "b64_cert": base64.b64encode(cert_pem).decode('utf-8'),  # Stringify & Base64 Encode
        "b64_key": base64.b64encode(key_pem).decode('utf-8'),  # Stringify & Base64 Encode
    })


def cert_val(request):
    return validate_client_cert(request)
