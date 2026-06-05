from django.http import JsonResponse
from django.urls import path


def ok(request):
    return JsonResponse({"ok": True})

urlpatterns = [path("ok/", ok)]
