import os
from celery import Celery

# Protect multiprocessing startup on Windows
if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Authentication_microService.settings")

app = Celery("authentication")

app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
