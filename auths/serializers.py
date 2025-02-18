from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name',
                  'last_name', 'address', 'phone_number')


class UserRegisterSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def to_representation(self, instance): 
        ret = super().to_representation(instance)
        ret.pop('password', None)
        return ret

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError(
                {"error": "Passwords do not match."})

        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError(
                {"email": "Email already exists."})

        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError(
                {"username": "Username already exists."})

        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        user = User.objects.create(**validated_data)
        user.set_password(validated_data['password'])
        user.is_active = False
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    identifier = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        identifier = data['identifier']
        password = data['password']

        # Find user either by username or email
        user = None
        if '@' in identifier and '.' in identifier:  # If identifier is an email
            user = User.objects.filter(email=identifier).first()
        else:
            user = User.objects.filter(username=identifier).first()

        # If the user is not found, raise an error
        if not user:
            raise serializers.ValidationError(
                "Invalid credentials. Please check your email or password.")

        # Check if the user is active and verified before password authentication
        if not user.is_active:
            raise serializers.ValidationError(
                "Your account is not active. Please check your email to verify your account.")

        # Authenticate the user with the provided password if the account is active and verified
        user = authenticate(username=user.username, password=password)

        if not user:
            raise serializers.ValidationError(
                "Invalid credentials. Please check your email or password.")

        return {"user": user}


class TokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField()


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
            return user
        except User.DoesNotExist:
            raise serializers.ValidationError(
                "User with this email does not exist.")


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=6)
    confirm_password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError(
                "New password and confirmation password do not match.")
        return data


class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, min_length=6)
    confirm_password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError(
                "New password and confirmation password do not match.")
        return data
