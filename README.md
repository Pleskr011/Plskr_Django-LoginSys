(WIP) Login System Backend with Django and DRF (Django REST Framework) for learning purposes. It works alongisde its Vue3 Frontend

The purpose of this project is to get a better understanding of Django as a backend and API REST development.

As far as now, this project has API endpoints for login, register, activate MFA via authenticator app (MFA via Django's console email by default), recovery password via email code. A basic chatroom is implmented via Django templates, but not integrated to the main app yet. 

Points of interests:
- loginApp/urls.py: The API endpoints 
- loginApp/views.py: All the logic behind the API endpoints
- seclogin/settings.py: The Django project configuration file
- loginApp/serializers.py: they help ensure that data is in the correct format and validate it before saving it to the database.
- loginApp/tests/: Folder with files for testing purposes. Using pytest for this.
- A Dockerfile to containerize it. Used alongside frontend (Vue.js/Nginx) and database (postgreSQL) with Docker Compose. 

Features to be implemented: 
- Deactivate MFA via authenticator,
- Deactivate MFA via email (just email and password in the login)
- Add recovery codes
- Add features for logged-in users (Currently learning to implement group chats (websockets and Redis)).
