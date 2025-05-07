from rest_framework.test import APITestCase
from rest_framework import status

class RegistrationTestCase(APITestCase):
    def test_successful_registration(self):
        data = {
            "email": "test@example.com",
            "first_name": "test",
            "last_name": "example",
            "password": "strongpassword",
            "password2": "strongpassword"
        }
        response = self.client.post('/sec/api/register/', data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_missing_fields(self):
        data = {
            "last_name": "example",
            "password": "strongpassword"
        }
        response = self.client.post('/sec/api/register/', data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)