from django import template
from django.utils.translation import gettext as _

register = template.Library()


@register.filter
def translate_text(value):
    # Stored audit actions are stable message IDs; user-entered names are never translated.
    return _(value)


@register.filter
def job_state(value):
    return {'idle': _('Aucune opération'), 'running': _('En cours'), 'complete': _('Terminée'), 'failed': _('Échec')}.get(value, _('Indisponible'))


@register.filter
def job_message(value):
    if not value:
        return ''
    if value.startswith('Échec de l’opération'):
        return _('Échec de l’opération. Consultez les journaux depuis la console.')
    return _(value)
