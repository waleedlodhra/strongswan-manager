from django import template
from django.template.loader import render_to_string
from ..wrapper.wrapper import ViciWrapper, ViciSocketException
from ..wrapper.exception import ViciException

register = template.Library()


@register.simple_tag(name="vici_reachable")
def vici_reachable():
    try:
        ViciWrapper()
        return {'reachable': True}
    except ViciException as e:
        return {'reachable': False, 'message': str(e)}


@register.simple_tag(name="vici_version_supported")
def vici_version_supported():
    try:
        vici_wrapper = ViciWrapper()
        version_info = vici_wrapper.get_version()
        raw = version_info.get('version', b'0.0')
        version = raw.decode('utf-8') if isinstance(raw, bytes) else str(raw)
        parts = version.split('.')
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        if major > 5:
            return True
        return major == 5 and minor >= 4
    except Exception:
        return True


@register.simple_tag(name="vici_checker")
def vici_checker():
    return render_to_string('vici/checker.html')
