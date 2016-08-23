from django.conf.urls import url
from django.contrib import admin
from api.views import api_upload, api_get_firmware, api_get_hierarchy, api_get_firmware_summary
from api.views import api_get_file, api_get_latest, api_get_stats, api_search

urlpatterns = [
    url(r'^upload/?$', api_upload, name='api_upload'),
    url(r'^latest/?$', api_get_latest, name='api_get_latest'),
    url(r'^stats/?$', api_get_stats, name='api_get_stats'),
    url(r'^search/?$', api_search, name='api_search'),
    url(r'^firmware/hierarchy/(?P<hash>[^/]+)/?$', api_get_hierarchy, name='api_get_hierarchy'),
    url(r'^firmware/summary/(?P<hash>[^/]+)/?$', api_get_firmware_summary, name='api_get_firmware_summary'),
    url(r'^firmware/(?P<hash>[^/]+)/?$', api_get_firmware, name='api_get_firmware'),
    url(r'^file/(?P<hash>[^/]+)/?$', api_get_file, name='api_get_file')
]
