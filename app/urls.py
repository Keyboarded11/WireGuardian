from django.urls import path
from panel import views
from django.views.i18n import set_language

urlpatterns = [
    path('language/', set_language, name='set_language'),
    path('', views.overview, name='overview'),
    path('connexion/', views.sign_in, name='login'),
    path('verification/', views.otp, name='otp'),
    path('verification/qr/', views.otp_qr, name='otp_qr'),
    path('deconnexion/', views.sign_out, name='logout'),
    path('appareils/', views.peers, name='peers'),
    path('appareils/ajouter/', views.peer_add, name='peer_add'),
    path('appareils/<int:pk>/', views.peer_action, name='peer_action'),
    path('appareils/<int:pk>/profil/', views.peer_profile, name='peer_profile'),
    path('appareils/limite/', views.client_limit, name='client_limit'),
    path('appliquer/', views.apply, name='apply'),
    path('reseau/', views.network, name='network'),
    path('utilisateurs/', views.users, name='users'),
    path('utilisateurs/<int:pk>/options/', views.user_options, name='user_options'),
    path('utilisateurs/ajouter/', views.user_add, name='user_add'),
    path('utilisateurs/<int:pk>/', views.user_toggle, name='user_toggle'),
    path('securite/', views.security, name='security'),
    path('securite/activer/', views.enable_2fa, name='enable_2fa'),
    path('securite/desactiver/', views.disable_2fa, name='disable_2fa'),
    path('journal/', views.journal, name='journal'),
    path('maintenance/', views.maintenance, name='maintenance'),
    path('maintenance/action/', views.maintenance_action, name='maintenance_action'),
]
