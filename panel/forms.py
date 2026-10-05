from django.utils.translation import gettext_lazy as _, gettext_noop as N
import re
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class PeerForm(forms.Form):
    name = forms.CharField(label=_('Nom de l’appareil'), max_length=64)
    internet = forms.BooleanField(label=_('Tunnel complet : Internet via le VPN'), required=False, help_text=_('Désactivé : tunnel fractionné, Internet reste direct. Activé : IPv4 via le VPN, IPv6 bloqué dans le tunnel pour éviter une fuite.'))


class EndpointForm(forms.Form):
    endpoint = forms.CharField(label=_('Adresse IP publique ou nom DNS'), max_length=253, help_text=_('Sans protocole ni port. Le port est défini à l’installation.'))

    def clean_endpoint(self):
        value = self.cleaned_data['endpoint'].lower().strip()
        if not re.fullmatch(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value) or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
            raise forms.ValidationError(_('Indiquez une adresse IPv4 ou un nom DNS valide.'))
        return value


class AccountForm(UserCreationForm):
    role = forms.ChoiceField(label=_('Rôle'), choices=[('reader', _('Lecture seule')), ('admin', _('Administrateur'))])

    class Meta:
        model = User
        fields = ['username', 'password1', 'password2', 'role']


class NetworkForm(EndpointForm):
    port = forms.IntegerField(label=_('Port WireGuard UDP'), min_value=1, max_value=65535)
    lan_networks = forms.CharField(label=_('Réseaux LAN'), help_text=_('Sous-réseaux IPv4 séparés par des virgules, par exemple 172.20.10.0/24, 172.20.20.0/24.'))
    interface = forms.RegexField(label=_('Interface réseau de sortie'), regex=r'^[a-zA-Z0-9_.-]{1,15}$')
    dns = forms.GenericIPAddressField(label=_('DNS des profils clients'), protocol='IPv4', required=False)

    def clean_lan_networks(self):
        from deploy.core import network
        try:
            values = [str(network(n.strip())) for n in self.cleaned_data['lan_networks'].split(',')]
            if not 1 <= len(values) <= 16:
                raise ValueError()
            return values
        except ValueError:
            raise forms.ValidationError(_('Indiquez entre 1 et 16 réseaux IPv4 valides.'))
