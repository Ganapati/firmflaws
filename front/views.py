from django.shortcuts import render
from django.http import Http404
from api.views import api_upload, api_get_hierarchy, api_get_firmware_summary
from api.views import api_get_file, api_get_latest, api_get_stats, api_search
import json


def home(request):
    """ Display home page
    """
    results = api_get_stats(request)
    json_result = json.loads(results.content.decode("utf-8"))
    print(json_result)
    return render(request, 'front/home.html', {'stats': json_result})

def latest(request):
    """ Return latest analysis
    """
    results = api_get_latest(request)
    json_result = json.loads(results.content.decode("utf-8"))
    print(json_result)
    return render(request, 'front/latest.html', {'firmwares': json_result})
    pass

def search(request):
    """ Display search page
    """
    try:
        k = request.GET.get('keyword', False)
        results = api_search(request)
        json_result = json.loads(results.content.decode("utf-8"))
        print(json_result)
        return render(request, 'front/search.html', {'firmwares': json_result, 'keyword':k})
    except NotImplementedError:
        raise Http404('<h1>Not firmware found</h1>')

def upload(request):
    """ Display upload page
    """
    results = api_upload(request)
    json_result = json.loads(results.content.decode("utf-8"))
    print(json_result)
    return render(request, 'front/upload.html', {'upload': json_result})

def get_firmware_summary(request, hash):
    """ Display summary page for a firmware
    """
    results = api_get_firmware_summary(request, hash)
    json_result = json.loads(results.content.decode("utf-8"))
    results_hierarchy = api_get_hierarchy(request, hash)
    json_result_hierarchy = json.loads(results_hierarchy.content.decode("utf-8"))
    ordered_filelist = sorted(json_result_hierarchy['files'], key=lambda file: file['filename'])
    return render(request, 'front/summary.html', {'firmware': json_result, 'hierarchy': ordered_filelist})

def get_file(request, hash):
    """ Display file page
    """
    results = api_get_file(request, hash)
    json_result = json.loads(results.content.decode("utf-8"))
    print(json_result)
    return render(request, 'front/file.html', {'file': json_result})