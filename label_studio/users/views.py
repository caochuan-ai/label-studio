"""This file and its contents are licensed under the Apache License 2.0. Please see the included NOTICE for copyright information and LICENSE for a copy of the license.
"""
import logging
import requests

from core.feature_flags import flag_set
from core.middleware import enforce_csrf_checks
from core.utils.common import load_func
from django.conf import settings
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect, render, reverse
from django.utils.http import is_safe_url
from django.http import HttpResponseRedirect
from organizations.forms import OrganizationSignupForm
from organizations.models import Organization
from rest_framework.authtoken.models import Token
from users import forms
from users.functions import login, proceed_registration
from users.models import User

logger = logging.getLogger()


@login_required
def logout(request):
    auth.logout(request)
    if settings.HOSTNAME:
        redirect_url = settings.HOSTNAME
        if not redirect_url.endswith('/'):
            redirect_url += '/'
        return redirect(redirect_url)
    return redirect('/')


@enforce_csrf_checks
def user_signup(request):
    """Sign up page"""
    user = request.user
    next_page = request.GET.get('next')
    token = request.GET.get('token')

    # checks if the URL is a safe redirection.
    if not next_page or not is_safe_url(url=next_page, allowed_hosts=request.get_host()):
        next_page = reverse('projects:project-index')

    user_form = forms.UserSignupForm()
    organization_form = OrganizationSignupForm()

    if user.is_authenticated:
        return redirect(next_page)

    # make a new user
    if request.method == 'POST':
        organization = Organization.objects.first()
        if settings.DISABLE_SIGNUP_WITHOUT_LINK is True:
            if not (token and organization and token == organization.token):
                raise PermissionDenied()
        else:
            if token and organization and token != organization.token:
                raise PermissionDenied()

        user_form = forms.UserSignupForm(request.POST)
        organization_form = OrganizationSignupForm(request.POST)

        if user_form.is_valid():
            redirect_response = proceed_registration(request, user_form, organization_form, next_page)
            if redirect_response:
                return redirect_response

    if flag_set('fflag_feat_front_lsdv_e_297_increase_oss_to_enterprise_adoption_short'):
        return render(
            request,
            'users/new-ui/user_signup.html',
            {
                'user_form': user_form,
                'organization_form': organization_form,
                'next': next_page,
                'token': token,
            },
        )

    return render(
        request,
        'users/user_signup.html',
        {
            'user_form': user_form,
            'organization_form': organization_form,
            'next': next_page,
            'token': token,
        },
    )


@enforce_csrf_checks
def casdoor_login(request):
    """Casdoor Login page"""
    return HttpResponseRedirect(
        f"{settings.CASDOOR_PATH}&redirect_uri={settings.CALL_BACK_PATH}&scope=read&state=xxx")


def is_email_registered(email):
    # 查询是否存在匹配指定邮箱的用户
    return User.objects.filter(email=email).exists()


def get_profile(tokens):
    headers = {'Content-Type': 'application/json'}  # Set the content type to application/json
    user_auth_body = {
        "token": f"{tokens[0]}.{tokens[1]}.{tokens[2]}",
        "app_name": "labelstudio",
        "org_name": "ccai"
    }
    response = requests.post(settings.CCAI_PROFILE_PATH, json=user_auth_body, headers=headers)
    return response.json()


@enforce_csrf_checks
def casdoor_callback(request):
    organization_form = OrganizationSignupForm()

    if request.method == 'GET':
        auth_code = request.GET.get('code')
        user_auth_body = {
            "code": auth_code,
            "application_name": "labelstudio",
            "org_name": "ccai"
        }
        headers = {'Content-Type': 'application/json'}
        response = requests.post(settings.CCAI_LOGIN_PATH, json=user_auth_body, headers=headers)

        if response.status_code == 200:
            resp = response.json()
            token1, token2, token3 = resp.get('token').split(".")
            user_profile = get_profile([token1, token2, token3])

            email = user_profile.get('user').get("email")
            if not is_email_registered(email):
                # auto register user and login
                user_form = forms.UserSignupForm()
                user_form.cleaned_data = {}
                user_form.cleaned_data['email'] = email
                user_form.cleaned_data['password'] = token1[:forms.PASS_MAX_LENGTH]

                redirect_response = proceed_registration(request, user_form, organization_form,
                                                         reverse('projects:project-index'))
                return redirect_response
            else:
                # update password and login
                user = User.objects.get(email=email)
                new_password = token1[:forms.PASS_MAX_LENGTH]
                user.set_password(new_password)
                user.save()

                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                return redirect(reverse('projects:project-index'))

        else:
            return render(request, 'users/user_login.html')

    return render(request, 'users/user_login.html')


@enforce_csrf_checks
def user_login(request):
    """Login page"""
    user = request.user
    next_page = request.GET.get('next')

    # checks if the URL is a safe redirection.
    if not next_page or not is_safe_url(url=next_page, allowed_hosts=request.get_host()):
        next_page = reverse('projects:project-index')

    login_form = load_func(settings.USER_LOGIN_FORM)
    form = login_form()

    if user.is_authenticated:
        return redirect(next_page)

    if request.method == 'POST':
        form = login_form(request.POST)
        if form.is_valid():
            user = form.cleaned_data['user']
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            if form.cleaned_data['persist_session'] is not True:
                # Set the session to expire when the browser is closed
                request.session['keep_me_logged_in'] = False
                request.session.set_expiry(0)

            # user is organization member
            org_pk = Organization.find_by_user(user).pk
            user.active_organization_id = org_pk
            user.save(update_fields=['active_organization'])
            return redirect(next_page)

    if flag_set('fflag_feat_front_lsdv_e_297_increase_oss_to_enterprise_adoption_short'):
        return render(request, 'users/new-ui/user_login.html', {'form': form, 'next': next_page})

    return render(request, 'users/user_login.html', {'form': form, 'next': next_page})


@login_required
def user_account(request):
    user = request.user

    if user.active_organization is None and 'organization_pk' not in request.session:
        return redirect(reverse('main'))

    form = forms.UserProfileForm(instance=user)
    token = Token.objects.get(user=user)

    if request.method == 'POST':
        form = forms.UserProfileForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            return redirect(reverse('user-account'))

    return render(
        request,
        'users/user_account.html',
        {'settings': settings, 'user': user, 'user_profile_form': form, 'token': token},
    )
