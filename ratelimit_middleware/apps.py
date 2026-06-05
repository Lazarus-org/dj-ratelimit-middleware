from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class RatelimitMiddlewareConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "ratelimit_middleware"
    verbose_name = _("Django Ratelimit Middleware")

    def ready(self):
        from . import checks  # noqa: F401
