from django.conf.urls import url
from django.contrib import admin
from front.views import home, upload, search, get_firmware_summary, get_file, latest

urlpatterns = [
	url(r'^$', home, name='home'),
	url(r'^latest/?$', latest, name='latest'),
 	url(r'^upload/?$', upload, name='upload'),
    url(r'^search/?$', search, name='search'),
    url(r'^firmware/summary/(?P<hash>[^/]+)/?$', get_firmware_summary, name='get_firmware_summary'),
    url(r'^file/(?P<hash>[^/]+)/?$', get_file, name='get_file')
]