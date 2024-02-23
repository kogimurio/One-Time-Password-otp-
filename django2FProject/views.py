from datetime import datetime
import pyotp
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.decorators import login_required
from.utilis import send_otp
from django.contrib.auth.models import User

def login_view(request):
    error_message = None
    if request.POST:
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            send_otp(request)
            request.session['username'] = username
            return redirect('otp')
        else:
            error_message = 'Invalid username or password'
    return render(request, 'login.html', {'error_message': error_message})


def otp_view(request):
    error_message = None
    if request.POST:
        otp = request.POST['otp']
        username = request.session['username']

        otp_secret_key = request.session['otp_secret_key']
        otp_valid_date = request.session['otp_valid_date']

        if otp_secret_key and otp_valid_date is not None:
            valid_until = datetime.fromisoformat(otp_valid_date)

            if valid_until > datetime.now():
                totp = pyotp.TOTP(otp_secret_key, interval=60)
                if totp.verify(otp):
                    user = get_object_or_404(User, username=username)
                    login(request, user)

                    del request.session['otp_secret_key']
                    del request.session['otp_valid_date']

                    return redirect('home')
                else:
                    error_message = 'Invalid one time password'
            else:
                error_message = 'one time password has expire try to login again'
        else:
            error_message = 'oops something went wrong'
    return render(request, 'otp.html', {'error_message': error_message})


@login_required
def home(request):
    return render(request, 'index.html')


def logout_view(request):
    logout(request)
    return redirect('login')
