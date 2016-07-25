from django.conf.urls import url
from django.contrib import admin
from api.views import upload, get_firmware, get_hierarchy
from api.views import get_file, get_latest, get_stats, search

urlpatterns = [
    url(r'^upload/?$', upload, name='upload'),
    url(r'^latest/?$', get_latest, name='get_latest'),
    url(r'^stats/?$', get_stats, name='get_stats'),
    url(r'^search/?$', search, name='search'),
    url(r'^firmware/hierarchy/(?P<hash>[^/]+)/?$', get_hierarchy, name='get_hierarchy'),
    url(r'^firmware/(?P<hash>[^/]+)/?$', get_firmware, name='get_firmware'),
    url(r'^file/(?P<hash>[^/]+)/?$', get_file, name='get_file')
]
