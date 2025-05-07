from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate, login
import pyotp
from .models import CustomUser
from .serializers import userSerializer, LoginSerializer
# Create your views here.

@api_view(['GET'])
@authentication_classes([SessionAuthentication])
@permission_classes([IsAuthenticated])
def user_list(request):
    users = CustomUser.objects.all()
    serializer = userSerializer(users, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@authentication_classes([SessionAuthentication])
@permission_classes([IsAuthenticated])
def user_detail(request):
    first_name = request.user.first_name
    last_name = request.user.last_name
    isMFAEnabled = request.user.isMfaEnabled
    return Response({'first_name': first_name, 'last_name': last_name, 'isMFAEnabled': isMFAEnabled}, status=status.HTTP_200_OK)

@api_view(['POST'])
def user_create(request):
    #print('Start creating user process...')
    serializer = userSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        #print('User created! -- ', serializer.data)
    else:
        #print('Error')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.data)

@api_view(['POST'])
def auth_view(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        user = authenticate(request, email=email, password=password)
        #print("printing user...: ", email, password, user)      
        if user is not None:
            if user.isMfaEnabled:
                return Response({'message': 'Check your auth app', 'mfa': True}, status=status.HTTP_200_OK)
            send_mfa(email)
            #request.session['email'] = email
            #request.session.save()
            #print(request.session.get_expiry_date())
            return Response({'message': 'MFA code sent!', 'mfa': False}, status=status.HTTP_200_OK)
        else:
            print("user is None...")
            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

@api_view(['POST'])
def login_view(request):
    email = request.data.get('email')
    mfa_code = request.data.get('mfa_code')
    user = CustomUser.objects.filter(email=email).first()
    if user is not None:
        if user.isMfaEnabled:
            if check_otp(user.secret_key, mfa_code):
                login(request, user)
                print("Logged in!")
                return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
        if user.MFA_code == mfa_code:
            user.MFA_code = ''
            user.save()
            login(request, user)
            return Response({'message': 'Login successful'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid MFA code'}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        return Response({'error': 'Invalid email. Communicate with admin'}, status=status.HTTP_401_UNAUTHORIZED)

@authentication_classes([SessionAuthentication])
@permission_classes([IsAuthenticated])
@api_view(['POST'])
def verifyOTP(request):
    email = request.user.email
    mfa_code = request.data.get('mfa_code')
    user = CustomUser.objects.filter(email=email).first()
    if user is not None:
        if check_otp(user.secret_key, mfa_code):
            return Response({'message': 'Authenticator successfuly verified'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid MFA code'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['GET'])
def check_session(request):
    session = request.user.is_authenticated
    print('check session: ', session)
    if session:
        return Response({'Session': 'Session exists'}, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'Session does not exist'}, status=status.HTTP_401_UNAUTHORIZED)
    

@api_view(['POST'])
def send_recovery_email(request):
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
    try:
        user_obj = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_200_OK)
    # Generate a recovery token
    recovery_token = create_otp()
    user_obj.OTP_recovery = recovery_token
    user_obj.save()
    # Send the recovery email
    subject = 'Password Recovery - SecLogin'
    message = f'Introduce the following recovery token: {recovery_token}'
    send_mail(subject, message, settings.EMAIL_HOST_USER, [email])
    # Instead of a link use the generated code or OTP
    return Response({'message': 'Recovery email sent successfully'}, status=status.HTTP_200_OK)

@api_view(['POST'])
def check_recovery_token(request):
    email = request.data.get('email')
    recovery_token = request.data.get('code')
    try:
        user_obj = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_200_OK)
    if user_obj.OTP_recovery == recovery_token:
        user_obj.OTP_recovery = ''
        user_obj.save()
        return Response({'message': 'Recovery token is valid'}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Invalid recovery token'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def reset_password(request):
    email = request.data.get('email')
    new_password = request.data.get('password')
    confirm_password = request.data.get('password2')
    if new_password is None or confirm_password is None:
        return Response({'error': 'New password and confirm password are required'}, status=status.HTTP_400_BAD_REQUEST)
    if new_password != confirm_password:
        return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
    user_obj = CustomUser.objects.get(email=email)
    if user_obj is None:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    serializer = userSerializer(user_obj, data={'password':new_password}, partial=True)
    if serializer.is_valid():
        serializer.save()
    return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)

@authentication_classes([SessionAuthentication])
@permission_classes([IsAuthenticated])
@api_view(['POST'])
def logout_view(request):
    session = request.user.is_authenticated
    print(session)
    if session:
        request.session.flush()
        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

@authentication_classes([SessionAuthentication])
@permission_classes([IsAuthenticated])
@api_view(['POST'])
def activateMFA(request):
    email = request.user.email
    uri, secret_key = create_qrcode(email)
    try:
        user = CustomUser.objects.get(email=email)
    except CustomUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    user.secret_key = secret_key
    user.isMfaEnabled = True
    user.save()
    return Response({'message': 'QR code sent!', 'qr_uri': uri}, status=status.HTTP_200_OK)

# ---- utiliy -----
def send_mfa(email):
    user = CustomUser.objects.get(email=email)
    #secret_key = pyotp.random_base32()
    #totp = pyotp.TOTP(secret_key)
    mfa_code = create_otp()
    user.MFA_code = mfa_code
    user.save()
    subject = 'MFA Code'
    message = f'Your MFA code is: {mfa_code}'
    send_mail(subject, message, settings.EMAIL_HOST_USER, [email])

def create_otp():
    secret_key = pyotp.random_base32()
    totp = pyotp.TOTP(secret_key)
    return totp.now()

def create_qrcode(email):
    secret_key = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret_key).provisioning_uri(name=email, issuer_name='SecLogin')
    #img = qrcode.make(uri)
    #img.save('qrcode.png')
    return uri, secret_key

def check_otp(secret_key, otp):
    totp = pyotp.TOTP(secret_key)
    return totp.verify(otp)