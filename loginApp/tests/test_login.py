from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch
from ..models import CustomUser

class LoginTestCase(APITestCase):
    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email = "test@login.com",
            first_name= "test",
            last_name= "login",
            password= "strongpassword",
            is_active= True
        )

    def test_successful_login(self):
        response = self.client.post('/sec/api/auth/', {
            "email": "test@login.com",
            "password": "strongpassword"
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)


    @patch('loginApp.views.create_otp')
    def test_2fa_flow(self, mock_create_otp):
        mock_create_otp.return_value = "123456"  
        response = self.client.post('/sec/api/auth/', {
            "email": "test@login.com",
            "password": "strongpassword"
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test OTP verification
        otp_response = self.client.post('/sec/api/login/', {
            "mfa_code": "123456",
            "email": "test@login.com"
        })
        self.assertEqual(otp_response.status_code, status.HTTP_200_OK)

    def test_invalid_credentials(self):
        response = self.client.post('/sec/api/auth/', {
            "email": "test@login.com",
            "password": "wrongpassword"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)