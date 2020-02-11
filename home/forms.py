from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm,UsernameField
from django.contrib.auth.models import User
from django.utils.translation import gettext, gettext_lazy as _


class RegisterForm(UserCreationForm):
    email = forms.EmailField(max_length=100, widget= forms.EmailInput(attrs={'placeholder':'Email'}))
    username = forms.CharField(widget= forms.TextInput(attrs={'placeholder':'Username'}))
    password1 = forms.CharField(widget= forms.PasswordInput(attrs={'placeholder':'Password'}))
    password2 = forms.CharField(widget= forms.PasswordInput(attrs={'placeholder':'Password again'}))
    
    class Meta:
	    model = User
	    fields = ["username", "email", "password1", "password2"]

class AuthForm(AuthenticationForm):
    username = UsernameField(widget= forms.TextInput(attrs={'placeholder':'Username'}))
    password = forms.CharField(widget= forms.PasswordInput(attrs={'placeholder':'Password'}))

