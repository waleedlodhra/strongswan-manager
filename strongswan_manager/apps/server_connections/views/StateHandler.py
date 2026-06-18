from django.http import JsonResponse

from strongswan_manager.apps.connections.models import Connection


class StateHandler(object):
    def __init__(self, request, id):
        self.request = request
        self.id = id

    @property
    def connection(self):
        return Connection.objects.get(pk=self.id).subclass()

    def handle(self):
        response = dict(id=self.connection.id, success=True)
        response['state'] = self.connection.state
        return JsonResponse(response)
