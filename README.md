# django-mini-5-authentication

منبع : https://www.django-rest-framework.org/api-guide/authentication/

## Authentication
authentication -> identifying credentials

permission & throttling -> use those credentials to determine if the request should be permitted

in view: (authentication -> permission -> throttling -> other codes)

The `request.user` property will typically be set to an instance of the `contrib.auth` package's `User` class.

The `request.auth` property is used for any additional authentication information.

### How authentication is determined
REST call authentication classes and set `reauest.user` and `request.auth`.

if no class authenticates:
- `request.user` = `django.contrib.auth.models.AnonymousUser`
- `request.auth` = `None`

The value of `request.user` and `request.auth` for unauthenticated requests can be modified using the `UNAUTHENTICATED_USER` and `UNAUTHENTICATED_TOKEN` settings.

### Setting the authentication scheme
set in `settings`
``` python
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ]
}
```
set in `APIView`
``` python
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

class ExampleView(APIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        content = {
            'user': str(request.user),  # `django.contrib.auth.User` instance.
            'auth': str(request.auth),  # None
        }
        return Response(content)
```
set in `@api_view`
``` python
@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
@permission_classes([IsAuthenticated])
def example_view(request, format=None):
    content = {
        'user': str(request.user),  # `django.contrib.auth.User` instance.
        'auth': str(request.auth),  # None
    }
    return Response(content)
```

### Unauthorized and Forbidden responses
`HTTP 401 Unauthorized` responses must always include a WWW-Authenticate header, that instructs the client how to authenticate.

`HTTP 403 Permission Denied` responses do not include the WWW-Authenticate header.

The first authentication class set on the view is used when determining the type of response.

Note that when a request may successfully authenticate, but still be denied permission to perform the request -> `403 Permission Denied`

### Apache mod_wsgi specific configuration
[...](https://www.django-rest-framework.org/api-guide/authentication/#apache-mod_wsgi-specific-configuration)

## API Reference
### BasicAuthentication
`request.user` = `User`

`request.auth` = `None`

[HTTP Basic Authentication](https://tools.ietf.org/html/rfc2617), signed against a user's username and password (only for testing)

Note: If you use `BasicAuthentication` in production you must ensure that your API is only available over `https`. You should also ensure that your API clients will always re-request the username and password at login, and **will never store those details to persistent storage**.

### TokenAuthentication
`request.user` = `User`

`request.auth` = `rest_framework.authtoken.models.Token`

``` python
INSTALLED_APPS = [
    ...
    'rest_framework.authtoken'
]
# python3 manage.py migrate
```
- If you want to use a different keyword in the header, such as `Bearer`, simply subclass `TokenAuthentication` and set the `keyword` class variable.

request header:
- `Authorization`: 'Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b'

### Generating Tokens
**By using signals** for example `post_save`
``` python
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
```
``` python
from rest_framework.authtoken import views
urlpatterns += [
    path('api-token-auth/', views.obtain_auth_token)
]
```
Custom View
``` python
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response

class CustomAuthToken(ObtainAuthToken):

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        })
```
**admin** in `your_app/admin.py`:
``` python
from rest_framework.authtoken.admin import TokenAdmin

TokenAdmin.raw_id_fields = ['user']
```
**command** in `command line`:

get token -> `./manage.py drf_create_token <username>`

regenerate token -> `./manage.py drf_create_token -r <username>`

### SessionAuthentication
`request.user` = `User`

`request.auth` = `None`

Session authentication is appropriate for `AJAX` clients that are running in the same session context as your website.

If you're using an `AJAX-style` API with SessionAuthentication, you'll need to make sure you include a valid [CSRF](https://docs.djangoproject.com/en/stable/ref/csrf/#ajax) token for any `"unsafe" HTTP method` calls, such as `PUT`, `PATCH`, `POST` or `DELETE` requests.

this only authenticated requests require `CSRF` tokens, and `anonymous requests` may be sent `without CSRF` tokens.

### RemoteUserAuthentication
`request.user` = `User`

`request.auth` = `None`

This authentication scheme allows you to delegate authentication to your web server, which sets the `REMOTE_USER` environment variable.

By default, `RemoteUserBackend` creates User objects for usernames that don't already exist. To change this and other behaviour, consult the [Django documentation](https://docs.djangoproject.com/en/stable/howto/auth-remote-user/).

more info for web server's:
- [Apache Authentication How-To](https://httpd.apache.org/docs/2.4/howto/auth.html)
- [NGINX (Restricting Access)](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-http-basic-authentication/)

## Custom authentication
override `.authenticate(self, request)` by `BaseAuthentication`
- return `(user, auth)` for authenticated user
- return `None` for check other authentication classes
- return `AuthenticationFailed` for rase an error

you can also override `.authenticate_header()` for return `HTTP 401 Unauthorized` in response.

**Example**: The following example will authenticate any incoming request as the user given by the username in a custom request header named `'X-USERNAME'`.
``` python
from django.contrib.auth.models import User
from rest_framework import authentication
from rest_framework import exceptions

class ExampleAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        username = request.META.get('HTTP_X_USERNAME')
        if not username:
            return None

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('No such user')

        return (user, None)
```
