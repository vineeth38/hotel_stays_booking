from rest_framework import serializers
from .models  import Users,Booking

class SignupSerializer(serializers.Serializer):
    name = serializers.CharField()
    city = serializers.CharField()
    mobile = serializers.CharField()
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True) 
class VerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

class BookingSSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = "__all__"