import django.shortcuts
from django.http import HttpResponse
import moma_ws.settings as django_settings
from .models import PersonalFile
import os

# Create your views here.


def index(request, *args):
    return HttpResponse("Nothing here yet.")


def show_webpage(request, name):
    file_obj = django.shortcuts.get_object_or_404(PersonalFile, name=name)
    context = {
        'resource_name': file_obj.name,
        'resource_url': os.path.join(os.pardir, django_settings.MEDIA_ROOT + str(file_obj.file))
    }
    print(context)
    return django.shortcuts.render(request, 'personal/redirect_to_file.html', context=context)
