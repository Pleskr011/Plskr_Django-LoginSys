from rest_framework import serializers 
from django.core.validators import validate_email
from django.core.exceptions import ValidationError 
from django.contrib.auth.hashers import make_password
from .models import CustomUser

class userSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        exclude = ['MFA_code', 'OTP_recovery', 'secret_key']

    def validate_email(self, value):
        try:
            validate_email(value)
            if CustomUser.objects.filter(email=value).exists():
                raise serializers.ValidationError('Email already exists')
        except ValidationError:
            raise serializers.ValidationError('Invalid email address')
        return value

    def validate_first_name(self, value):
        if  len(value) < 2:
            raise serializers.ValidationError("First name must be at least 2 characters long.")
        return value

    def validate_last_name(self, value):
        if  len(value) < 2:
            raise serializers.ValidationError("Last name must be at least 2 characters long.")
        return value
    def validate_password(self, value):
        if len(value) < 8 or len(value) > 16:
            raise serializers.ValidationError("Password must be at least 8 characters long and less than 16 characters.")
        if 'password2' in self.initial_data and value != self.initial_data['password2']:
            raise serializers.ValidationError('Passwords do not match')
        value = make_password(value)
        return value
    
    def update(self, instance, validated_data):
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        instance.password = validated_data.get('password', instance.password)
        instance.save()
        return instance

    #def create(self, validated_data):
        # Create a new user instance
        #user = CustomUser.objects.create_user(**validated_data)
        #return user
class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=254, validators=[validate_email])
    class Meta:
        model = CustomUser
        fields = ['email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, values):
        email = values.get('email')
        password = values.get('password')
        user = CustomUser.objects.filter(email=email).first()
        if user is None:
            raise serializers.ValidationError('Email not found')
        if not user.check_password(password):
            raise serializers.ValidationError('Invalid password mi estimado')
        return values
    
    def validate_email(self, value):
        try:
            validate_email(value)
        except ValidationError:
            raise serializers.ValidationError('Invalid email address')
        return value
    
