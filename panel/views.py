from django.utils.translation import gettext as _, gettext_noop as N
import base64
import hashlib
import io
import time
from functools import wraps

import qrcode
from qrcode.image.svg import SvgPathImage
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm
from django.contrib.sessions.models import Session
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.db import transaction
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django_otp import verify_token
from django_otp.plugins.otp_totp.models import TOTPDevice

from . import agent_client
from .forms import AccountForm, NetworkForm, PeerForm
from .models import Audit, Configuration, Peer, RateBucket
from .policy import policy, client_routes, available_addresses


def audit(request, action, detail=''):
    Audit.objects.create(actor=request.user.username, action=action, detail=detail)


def protected(admin=False):
    def decorate(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')
            verified = request.session.get('verified_at', 0)
            if time.time() - verified > 28800:
                return redirect('otp')
            if admin and not request.user.is_staff:
                return HttpResponseForbidden(_('Accès réservé aux administrateurs.'))
            return view(request, *args, **kwargs)
        return wrapped
    return decorate


def limited(request):
    # Persisted, per-account AND per-source limits. No trust in X-Forwarded-For.
    now = time.time()
    blocked = False
    with transaction.atomic():
        RateBucket.objects.filter(start__lt=now - 900).delete()
        for value, maximum in [('ip:' + request.META.get('REMOTE_ADDR', ''), 30), ('user:' + request.POST.get('username', '').casefold(), 8)]:
            key = hashlib.sha256(value.encode()).hexdigest()
            bucket, _ = RateBucket.objects.get_or_create(key=key, defaults={'start': now})
            bucket.count += 1
            bucket.save(update_fields=['count'])
            blocked |= bucket.count > maximum
    return blocked


def sign_in(request):
    error = ''
    if request.method == 'POST':
        if limited(request):
            return render(request, 'login.html', {'error': _('Trop de tentatives. Réessayez dans 15 minutes.')}, status=429)
        user = authenticate(request, username=request.POST.get('username', ''), password=request.POST.get('password', ''))
        if user:
            login(request, user)
            request.session.pop('verified_at', None)
            request.session['password_at'] = time.time()
            if TOTPDevice.objects.filter(user=user, confirmed=True).exists():
                return redirect('otp')
            request.session['verified_at'] = time.time()
            audit(request, N('Connexion par mot de passe'))
            return redirect('overview')
        error = _('Identifiants incorrects.')
        Audit.objects.create(actor=_('anonyme'), action=N('Connexion refusée'))
    return render(request, 'login.html', {'error': error})


def otp(request):
    if not request.user.is_authenticated or time.time() - request.session.get('password_at', 0) > 300:
        logout(request)
        return redirect('login')
    if not TOTPDevice.objects.filter(user=request.user, confirmed=True).exists() and not request.session.get('enrolling_2fa'):
        return redirect('user_options', pk=request.user.pk)
    with transaction.atomic():
        device = TOTPDevice.objects.filter(user=request.user).first()
        if not device:
            device = TOTPDevice.objects.create(user=request.user, name='Authenticator', confirmed=False)
    error = ''
    if request.method == 'POST':
        validated = verify_token(request.user, device.persistent_id, request.POST.get('token', ''))
        if validated:
            validated.confirmed = True
            validated.save(update_fields=['confirmed'])
            if request.session.get('enrolling_2fa'):
                # Rotate the password hash's session authentication key without changing
                # the password: every pre-enrolment session must authenticate again.
                request.user.password = request.session.pop('enrollment_password_hash')
                request.user.save(update_fields=['password'])
                update_session_auth_hash(request, request.user)
            request.session.cycle_key()
            request.session['verified_at'] = time.time()
            request.session.pop('enrolling_2fa', None)
            audit(request, N('Connexion avec 2FA'))
            return redirect('overview')
        error = _('Code invalide, déjà utilisé ou temporairement bloqué.')
    return render(request, 'otp.html', {'enroll': not device.confirmed, 'uri': device.config_url if not device.confirmed else '', 'error': error})


def otp_qr(request):
    if not request.user.is_authenticated or time.time() - request.session.get('password_at', 0) > 300:
        return HttpResponseForbidden()
    device = get_object_or_404(TOTPDevice, user=request.user, confirmed=False)
    buffer = io.BytesIO()
    qrcode.make(device.config_url, image_factory=SvgPathImage).save(buffer)
    return HttpResponse(buffer.getvalue(), content_type='image/svg+xml')


@require_POST
def sign_out(request):
    logout(request)
    return redirect('login')


def config():
    return Configuration.objects.get_or_create(pk=1, defaults={'endpoint': policy()['endpoint']})[0]


def status():
    try:
        return agent_client.call('status'), ''
    except agent_client.AgentUnavailable as exc:
        return {}, str(exc)


@protected()
def overview(request):
    live, error = status()
    peers = list(Peer.objects.all().order_by('id'))
    for peer in peers:
        stats = live.get('peers', {}).get(peer.public_key, {})
        peer.last_handshake = stats.get('handshake', 0)
        peer.online = peer.last_handshake > time.time() - 180
        peer.rx = stats.get('rx', 0)
        peer.tx = stats.get('tx', 0)
    return render(request, 'overview.html', {'peers': peers, 'full_count': sum(p.internet for p in peers), 'online': sum(p.online for p in peers), 'live': live, 'agent_error': error, 'config': config(), 'events': Audit.objects.all()[:5], 'page': 'overview'})


@protected()
def peers(request):
    queryset = Peer.objects.order_by('id')
    query = request.GET.get('q', '')[:64]
    if query:
        queryset = queryset.filter(name__icontains=query)
    return render(request, 'peers.html', {'peers': queryset, 'q': query, 'config': config(), 'page': 'peers'})


def immediate_changes(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        try:
            return view(request, *args, **kwargs)
        except agent_client.AgentUnavailable as exc:
            messages.error(request, str(exc))
            return redirect('peers')
    return wrapped


def sync_clients(configuration):
    snapshot = [{'public_key': p.public_key, 'address': p.address, 'internet': p.internet} for p in Peer.objects.filter(enabled=True)]
    agent_client.call('sync', peers=snapshot)
    configuration.applied_revision = configuration.revision
    configuration.save(update_fields=['applied_revision'])


@protected(admin=True)
@immediate_changes
def peer_add(request):
    form = PeerForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        configuration = config()
        if not configuration.endpoint:
            form.add_error(None, _('Renseignez d’abord l’adresse publique dans Réseau.'))
        else:
            try:
                live = agent_client.call('status')
            except agent_client.AgentUnavailable as exc:
                form.add_error(None, str(exc))
            else:
                if form.cleaned_data['internet'] and not policy().get('dns'):
                    form.add_error('internet', _('Configurez un DNS dans Réseau avant de créer un profil en tunnel complet.'))
                    return render(request, 'form.html', {'form': form, 'title': _('Ajouter un appareil'), 'page': 'peers'})
                private = X25519PrivateKey.generate()
                public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
                with transaction.atomic():
                    configuration = Configuration.objects.select_for_update().get(pk=1)
                    existing = Peer.objects.filter(name__iexact=form.cleaned_data['name'].strip()).first()
                    if existing:
                        messages.info(request, _('Ce client existe déjà. Son adresse VPN est conservée.'))
                        return redirect('peer_profile', pk=existing.pk)
                    if configuration.max_clients and Peer.objects.count() >= configuration.max_clients:
                        messages.error(request, _('La limite de clients est atteinte.'))
                        return redirect('peers')
                    used = set(Peer.objects.values_list('address', flat=True))
                    address = next((ip for ip in available_addresses() if ip not in used), None)
                    if address is None:
                        form.add_error(None, _('Toutes les adresses disponibles sont utilisées.'))
                    else:
                        peer = Peer.objects.create(name=form.cleaned_data['name'], public_key=public, address=address, internet=form.cleaned_data['internet'])
                        configuration.revision += 1
                        configuration.save()
                        sync_clients(configuration)
                        audit(request, N('Appareil créé'), peer.name)
                if address:
                    secret = base64.b64encode(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
                    p = policy()
                    dns = f'DNS = {p["dns"]}\n' if p.get('dns') and peer.internet else ''
                    routes = ['0.0.0.0/0', '::/0'] if peer.internet else p['lan_networks'] + [p['vpn_address'] + '/32']
                    content = f'[Interface]\nPrivateKey = {secret}\nAddress = {address}/32\n{dns}\n[Peer]\nPublicKey = {live["public_key"]}\nEndpoint = {configuration.endpoint}:{p["port"]}\nAllowedIPs = {", ".join(routes)}\nPersistentKeepalive = 25\n'
                    return render(request, 'provision.html', {'peer': peer, 'client_config': content, 'page': 'peers'})
    return render(request, 'form.html', {'form': form, 'title': _('Ajouter un appareil'), 'description': _('Créez un profil et choisissez son mode de routage.'), 'page': 'peers'})


@require_POST
@protected(admin=True)
@immediate_changes
def peer_action(request, pk):
    with transaction.atomic():
        configuration = Configuration.objects.select_for_update().get(pk=1)
        peer = get_object_or_404(Peer, pk=pk)
        action = request.POST.get('action')
        if action not in ('toggle', 'delete', 'internet'):
            return HttpResponse(_('Action invalide'), status=400)
        audit(request, N('Appareil supprimé') if action == 'delete' else N('État de l’appareil modifié'), peer.name)
        if action == 'delete':
            peer.delete()
        elif action == 'internet':
            if not peer.internet and not policy().get('dns'):
                messages.error(request, _('Configurez un DNS dans Réseau avant d’activer un tunnel complet.'))
                return redirect('peers')
            peer.internet = not peer.internet
            peer.save()
        else:
            peer.enabled = not peer.enabled
            peer.save()
        configuration.revision += 1
        configuration.save()
        sync_clients(configuration)
    messages.info(request, _('Modification appliquée. Après un changement de routage, mettez aussi à jour le profil client.'))
    return redirect('peers')


@require_POST
@protected(admin=True)
def apply(request):
    try:
        with transaction.atomic():
            configuration = Configuration.objects.select_for_update().get(pk=1)
            snapshot = [{'public_key': p.public_key, 'address': p.address, 'internet': p.internet} for p in Peer.objects.filter(enabled=True)]
            agent_client.call('sync', peers=snapshot)
            configuration.applied_revision = configuration.revision
            configuration.save()
            audit(request, N('Configuration WireGuard appliquée'), str(len(snapshot)))
        messages.success(request, _('Configuration appliquée au tunnel WireGuard.'))
    except agent_client.AgentUnavailable as exc:
        messages.error(request, str(exc))
    return redirect('peers')


@protected(admin=True)
def network(request):
    configuration = config()
    initial = {**policy(), 'endpoint': configuration.endpoint, 'lan_networks': ', '.join(policy()['lan_networks'])}
    form = NetworkForm(request.POST or None, initial=initial)
    if request.method == 'POST' and form.is_valid():
        if not request.user.check_password(request.POST.get('confirm_password', '')):
            form.add_error(None, _('Confirmez votre mot de passe pour modifier le réseau.'))
        else:
            try:
                agent_client.call('configure', policy={**policy(), **form.cleaned_data})
            except agent_client.AgentUnavailable as exc:
                form.add_error(None, str(exc))
            else:
                configuration.endpoint = form.cleaned_data['endpoint']
                configuration.save(update_fields=['endpoint'])
                audit(request, N('Paramètres réseau modifiés'), configuration.endpoint)
                messages.success(request, _('Réseau appliqué. Mettez à jour les profils clients et la redirection du routeur si le port a changé.'))
                return redirect('network')
    return render(request, 'network.html', {'form': form, 'policy': policy(), 'page': 'network'})


@protected()
def users(request):
    accounts = User.objects.order_by('username') if request.user.is_staff else User.objects.filter(pk=request.user.pk)
    enabled = set(TOTPDevice.objects.filter(confirmed=True).values_list('user_id', flat=True))
    for account in accounts:
        account.two_factor = account.pk in enabled
    return render(request, 'users.html', {'accounts': accounts, 'page': 'users'})


@require_POST
@protected(admin=True)
def client_limit(request):
    try:
        limit = int(request.POST.get('max_clients', ''))
        if not 0 <= limit <= 1021:
            raise ValueError()
    except ValueError:
        return HttpResponse(_('Action invalide'), status=400)
    with transaction.atomic():
        c = Configuration.objects.select_for_update().get(pk=1)
        if limit and limit < Peer.objects.count():
            messages.error(request, _('La limite doit couvrir les clients existants.'))
        else:
            c.max_clients = limit
            c.save(update_fields=['max_clients'])
            audit(request, N('Limite de clients modifiée'), str(limit))
    return redirect('peers')


@protected(admin=True)
def user_add(request):
    form = AccountForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save(commit=False)
        user.is_staff = form.cleaned_data['role'] == 'admin'
        user.save()
        audit(request, N('Utilisateur créé'), user.username)
        messages.success(request, _('Compte créé. Gérez son mot de passe et sa 2FA dans ses options.'))
        return redirect('users')
    return render(request, 'form.html', {'form': form, 'title': _('Créer un utilisateur'), 'description': _('Transmettez le mot de passe initial par un canal sûr. Aucun compte partagé.'), 'page': 'users'})


@require_POST
@protected(admin=True)
def user_toggle(request, pk):
    user = get_object_or_404(User, pk=pk)
    if user.pk == request.user.pk or user.is_superuser:
        return HttpResponseForbidden(_('Ce compte ne peut pas être désactivé ici.'))
    user.is_active = not user.is_active
    user.save(update_fields=['is_active'])
    audit(request, N('Accès utilisateur modifié'), user.username)
    return redirect('users')


@protected()
def security(request):
    return user_options(request, request.user.pk)


@protected()
def user_options(request, pk):
    account = get_object_or_404(User, pk=pk)
    own = account.pk == request.user.pk
    if not own and (not request.user.is_staff or (account.is_superuser and not request.user.is_superuser)):
        return HttpResponseForbidden()
    form = (PasswordChangeForm if own else SetPasswordForm)(account, request.POST or None)
    if request.method == 'POST':
        if not own and not request.user.check_password(request.POST.get('actor_password', '')):
            return HttpResponseForbidden(_('Mot de passe incorrect.'))
        if request.POST.get('action') == 'reset_2fa':
            if own:
                return HttpResponseForbidden()
            with transaction.atomic():
                TOTPDevice.objects.filter(user=account).delete()
                for session in Session.objects.all():
                    if str(session.get_decoded().get('_auth_user_id')) == str(account.pk):
                        session.delete()
                audit(request, N('2FA réinitialisée'), account.username)
            messages.success(request, _('2FA réinitialisée. Cet utilisateur devra la configurer à nouveau.'))
            return redirect('user_options', pk=account.pk)
        if form.is_valid():
            user = form.save()
            if own:
                update_session_auth_hash(request, user)
            audit(request, N('Mot de passe modifié'), account.username)
            messages.success(request, _('Mot de passe modifié. Les autres sessions sont invalidées.'))
            return redirect('user_options', pk=account.pk)
    return render(request, 'security.html', {'account': account, 'own_account': own, 'form': form, 'two_factor': TOTPDevice.objects.filter(user=account, confirmed=True).exists(), 'page': 'users'})


@require_POST
@protected()
def enable_2fa(request):
    if not request.user.check_password(request.POST.get('password', '')):
        return HttpResponseForbidden(_('Mot de passe incorrect.'))
    request.session['password_at'] = time.time()
    request.session['enrolling_2fa'] = True
    request.session['enrollment_password_hash'] = make_password(request.POST['password'])
    return redirect('otp')


@require_POST
@protected()
def disable_2fa(request):
    device = TOTPDevice.objects.filter(user=request.user, confirmed=True).first()
    if not request.user.check_password(request.POST.get('password', '')) or not device or not verify_token(request.user, device.persistent_id, request.POST.get('token', '')):
        return HttpResponseForbidden(_('Mot de passe ou code incorrect.'))
    device.delete()
    # Invalidate all other sessions by rotating the password hash with same password.
    request.user.set_password(request.POST['password'])
    request.user.save(update_fields=['password'])
    update_session_auth_hash(request, request.user)
    audit(request, N('2FA désactivée'))
    messages.success(request, _('Double authentification désactivée.'))
    return redirect('user_options', pk=request.user.pk)


@protected(admin=True)
def journal(request):
    from django.core.paginator import Paginator
    entries = Paginator(Audit.objects.all(), 50).get_page(request.GET.get('p'))
    return render(request, 'journal.html', {'entries': entries, 'page': 'journal'})


@protected(admin=True)
def peer_profile(request, pk):
    peer = get_object_or_404(Peer, pk=pk)
    p = policy()
    routes = ['0.0.0.0/0', '::/0'] if peer.internet else p['lan_networks'] + [p['vpn_address'] + '/32']
    return render(request, 'profile.html', {'peer': peer, 'routes': ', '.join(routes), 'config': config(), 'page': 'peers'})


@protected(admin=True)
def maintenance(request):
    try:
        result = agent_client.call('maintenance_status')
        error = ''
    except agent_client.AgentUnavailable as exc:
        result, error = {}, str(exc)
    return render(request, 'maintenance.html', {'job': result.get('job', {}), 'agent_error': error, 'page': 'maintenance'})


@require_POST
@protected(admin=True)
def maintenance_action(request):
    operation = request.POST.get('operation')
    if operation not in ('update_system', 'update_app', 'backup', 'download_backup'):
        return HttpResponse(_('Action inconnue'), status=400)
    if not request.user.check_password(request.POST.get('password', '')):
        return HttpResponseForbidden(_('Mot de passe incorrect.'))
    kwargs = {}
    if operation == 'backup':
        password = request.POST.get('backup_password', '')
        if len(password) < 14 or password != request.POST.get('backup_confirmation'):
            messages.error(request, _('La phrase de sauvegarde doit contenir 14 caractères minimum et les deux saisies doivent correspondre.'))
            return redirect('maintenance')
        kwargs['password'] = password
    try:
        result = agent_client.call(operation, **kwargs)
        audit(request, {'backup': N('Sauvegarde demandée'), 'download_backup': N('Sauvegarde téléchargée'), 'update_system': N('Mise à jour système demandée'), 'update_app': N('Mise à jour applicative demandée')}[operation])
        if operation == 'download_backup':
            response = HttpResponse(base64.b64decode(result['archive']), content_type='application/octet-stream')
            response['Content-Disposition'] = 'attachment; filename="wireguardian-backup.kwg"'
            return response
        messages.success(request, _('Demande transmise. Actualisez le suivi pour connaître le résultat ; une seule opération peut s’exécuter à la fois.'))
    except agent_client.AgentUnavailable as exc:
        messages.error(request, str(exc))
    return redirect('maintenance')
