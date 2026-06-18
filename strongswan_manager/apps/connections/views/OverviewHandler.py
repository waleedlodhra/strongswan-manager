from django.contrib import messages
from django.shortcuts import render
from django_tables2 import RequestConfig

from strongswan_manager.apps.connections.models.connections import Connection
from strongswan_manager.helper_apps.vici.wrapper.exception import ViciException
from ..tables import ConnectionTable


class OverviewHandler(object):
    def __init__(self, request):
        self.request = request
        self.ENTRIES_PER_PAGE = 10

    def handle(self):
        try:
            return self._render()
        except Exception as e:
            if isinstance(e, ViciException):
                messages.warning(self.request, str(e))
            else:
                messages.error(self.request, f"Unexpected error loading connections: {e}")
            return render(self.request, 'connections/overview.html', {'table': None})

    def _render(self):
        queryset = Connection.objects.all()
        table = ConnectionTable(queryset, request=self.request)
        RequestConfig(self.request, paginate={"per_page": self.ENTRIES_PER_PAGE}).configure(table)
        if len(queryset) == 0:
            table = None
        return render(self.request, 'connections/overview.html', {'table': table})
