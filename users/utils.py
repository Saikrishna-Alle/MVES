from rest_framework.response import Response
from rest_framework import status
from users.models import UserRoles


def check_user_authorization(user_id, required_roles):
    try:
        user = UserRoles.objects.get(user_id=user_id)
        if user.user_type not in required_roles:
            return False, Response({'error': 'You are not authorized to perform this action'}, status=status.HTTP_401_UNAUTHORIZED)
    except UserRoles.DoesNotExist:
        return False, Response({'error': 'Login Again'}, status=status.HTTP_404_NOT_FOUND)
    return True, None
