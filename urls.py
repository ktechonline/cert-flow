from django.urls import path
from . import views as cert

urlpatterns = [
  path('cert/gen/<str:unit_type>/<int:qty>/', cert.cert_gen, name='cert_gen'),
  path('cert/val/', cert.cert_val, name='cert_val'),
]
