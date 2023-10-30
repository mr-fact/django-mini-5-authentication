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

`HTTP 403 Unauthorized` responses do not include the WWW-Authenticate header.

The first authentication class set on the view is used when determining the type of response.

Note that when a request may successfully authenticate, but still be denied permission to perform the request -> `403 Permission Denied`

### Apache mod_wsgi specific configuration
[...](https://www.django-rest-framework.org/api-guide/authentication/#apache-mod_wsgi-specific-configuration)

## API Reference
