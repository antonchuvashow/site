from django.shortcuts import render, redirect, HttpResponse
from .forms import RegisterForm, AuthForm
from django.contrib.auth import authenticate, login
from django.contrib import messages 
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import EmailMultiAlternatives 
from django.template.loader import get_template 
from django.template import Context 
from django.contrib.auth.models import User
from django.contrib.auth import logout
from .tokens import account_activation_token
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

def home(request):
    return render(request, 'home.html', {})

def register(request): 
    if request.method == 'POST': 
        form = RegisterForm(request.POST) 
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            subject = 'Activate account'
            current_site = get_current_site(request)
            message = render_to_string('acac.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': str(urlsafe_base64_encode(force_bytes(user.pk))),
                'token': str(account_activation_token.make_token(user)),
            })
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [form.cleaned_data.get('email'),]
            send_mail( subject, message, email_from, recipient_list )
            return redirect('login') 
    else: 
        form = RegisterForm() 
    return render(request, 'registration/register.html', {'form': form, 'title':'reqister here'}) 
   

def login_request(request):
    if request.method == 'POST':
        form = AuthForm(request=request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None and user.is_active == True:
                login(request, user)
                return redirect('/')
    form = AuthForm()
    return render(request = request,
                    template_name = "registration/login.html",
                    context={"form":form})
def logout_view(request):
    logout(request)
    messages.info(request, "Logged out successfully!")
    return redirect("home")

def activate(request, cpuser, token):
    try:
        user = User.objects.get(pk=force_text(urlsafe_base64_decode(cpuser)))
    except:
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        return redirect("home")
    else:
        return HttpResponse('Activation link is invalid!')