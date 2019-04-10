"""caronte URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf.urls.static import static

from caronte_server.views import CRAuth
from caronte_server.views import Registration
from caronte_server.views import Validator
from caronte_server.views import SampleProvider

from .settings import STATIC_URL
from .settings import STATICFILES_DIRS

urlpatterns = [
    path('admin/', admin.site.urls),
    path('crauth/', CRAuth.as_view()),
    path('validate/', Validator.as_view()),
    path('register/', Registration.as_view()),
    path('provider/', SampleProvider.as_view())
] + static(STATIC_URL, document_root=STATICFILES_DIRS[0])
