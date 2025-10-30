from django.shortcuts import render
from rest_framework import status
from django.http import HttpResponse,JsonResponse
from .serializers import SignupSerializer,VerifySerializer,BookingSSerializer
from .models import Users,OTP,Booking
from .utils import generate_and_send_otp
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.authentication import JWTAuthentication
User = get_user_model()
import json
import jwt
from datetime import datetime,timedelta
import bcrypt
from rest_framework.decorators import api_view
SECRET_KEY = 'django-insecure-j^8f*ukxchybdc&0ajrj=8d-s3n*t%r)u(b6q2)8x00pd5)*uc'
# Create your views here.
def sample(self):
    return HttpResponse("Auth app is working")
@csrf_exempt
def Signup(request):
    if request.method == "POST":
        try:
            # Parse JSON body into a dict
            data = json.loads(request.body)

            # Pass the dict to serializer
            serializer = SignupSerializer(data=data)

            if not serializer.is_valid():
                return JsonResponse({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

            validated_data = serializer.validated_data
            email = validated_data['email'].lower()
            # request.session['pending_password'] = validated_data['password']
            # request.session.modified = True
            # check if verified user already exists
            if Users.objects.filter(email=email).exists():
                return JsonResponse(
                    {'message': 'User already exists with this email'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # save data temporarily in OTP table
            OTP.objects.filter(email=email).delete()
            pswd = validated_data['password'].encode('utf-8')
            salt=bcrypt.gensalt(12)
            hashed_pswd= bcrypt.hashpw(pswd,salt).decode("utf-8")
            otp_instance = OTP.objects.create(
                email=email,
                code=generate_and_send_otp(email),
                name=validated_data['name'],
                city=validated_data['city'],
                mobile=validated_data['mobile'],
                password=hashed_pswd,
            )

            return JsonResponse({'message': 'OTP sent to email'})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=status.HTTP_400_BAD_REQUEST)
    else:
        return JsonResponse({'error': 'Only POST allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    # if request.method == "POST":

    #     serializer = SignupSerializer(data=req.body)
    #     print(serializer.is_valid())
    #     data = serializer.validated_data
    #     print(data)
    #     email=data['email'].lower()

    #     # check if verified user already exists
    #     if Users.objects.filter(email=email).exists():
    #        return JsonResponse({'message': 'User already exists with this email'}, status=status.HTTP_400_BAD_REQUEST)
    
    #     # save data temporarily in OTP table
    #     OTP.objects.filter(email=email).delete()
    #     otp_instance =  OTP.objects.create(
    #         email=email,
    #         code=generate_and_send_otp(email),
    #         name=data['name'],
    #         city=data['city'],
    #         mobile=data['mobile'],
    #         password=data['password'],
    #     )

    #     return JsonResponse({'message': 'OTP sent to email'})
@csrf_exempt
def VerifyOTP(request):
    print("✅ Django reached VerifyOTP view")
    if request.method != "POST":
        return JsonResponse({'error': 'Only POST allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    if request.method != "POST":
        return JsonResponse({'error': 'Only POST allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    try:
        data = json.loads(request.body)
        print("📦 Received data:", data)
    except Exception as e:
        print("❌ JSON decode failed:", e)
        return JsonResponse({'error': 'Invalid JSON'}, status=status.HTTP_400_BAD_REQUEST)

    serializer = VerifySerializer(data=data)
    if not serializer.is_valid():
        print("❌ Serializer errors:", serializer.errors)
        return JsonResponse({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    validated_data = serializer.validated_data
    print("✅ Serializer valid, validated_data:", validated_data)
    validated_data = serializer.validated_data
    email = validated_data['email'].lower()
    otp_code = validated_data['otp']

    # Get latest OTP for this email
    otp = OTP.objects.filter(email=email, code=otp_code).order_by('-created_at').first()
    print(otp)
    if not otp or not otp.is_valid():
        return JsonResponse({'message': 'OTP did not match or expired'}, status=status.HTTP_400_BAD_REQUEST)
    # print(request.session['pending_password'])
    # password= request.session['pending_password'].encode("utf-8")
    # salt=bcrypt.gensalt(12)
    # hashed_pswd= bcrypt.hashpw(password,salt).decode("utf-8")
    # print(hashed_pswd)
    # Create user now
    user = Users.objects.create(
        email=email,
        name=otp.name,
        city=otp.city,
        mobile=otp.mobile,
        password=otp.password
    )

    # Delete used OTPs
    OTP.objects.filter(email=email).delete()
    user_details= {
        "id":user.id,
        "email":user.email,
        "name":user.name,
        "logged_in":True
    }
    print(user.email,user.name)
    print(user.__dict__)
    # jwt_token=jwt.encode(user_details,SECRET_KEY,"HS256")
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    response = JsonResponse({
        "message": "Verified successfully",
        "access": access_token,
        "refresh": str(refresh),
        "user": user_details
    })
    response.set_cookie(
        key="access",
        value=access_token,
        max_age=60 * 15,  # 15 minutes
        httponly=True,
        secure=False,     # True in production
        samesite="Lax"
    )
    response.set_cookie(
        key="refresh",
        value=str(refresh),
        max_age=60 * 60 * 24 * 7,  # 7 days
        httponly=True,
        secure=False,              # True in production
        samesite="Lax"
    )
    return response
    # refresh = RefreshToken.for_user(user_details)
    # response = JsonResponse({'message': 'Verified successfully','token': jwt_token,'user': user_details}) 
    # response.set_cookie(
    # key='access',
    # value=str(refresh.access_token),
    # max_age=3600,
    # httponly=True,
    # secure=False,        # set True in production (HTTPS)
    # samesite='None'
    # 
    # response.set_cookie(
    # key='token',
    # value=jwt_token,
    # max_age=3600,
    # httponly=True,
    # secure=False,
    # samesite='None'
    # )
    # return response

@csrf_exempt
def login(req):
    if req.method=="POST":
        try:
            data = json.loads(req.body.decode("utf-8"))
            print("🟢 Received data:", data)
            email = data.get("email")
            password = data.get("password")

            try:
                user = Users.objects.get(email=email)
                print("✅ User found:", user.email)
            except Users.DoesNotExist:
                print("❌ User not found")
                return JsonResponse({"error":"Invalid email or password"}, status=400)
            stored_hashed_pw  = user.password.encode("utf-8")
            entered_pw = password.encode("utf-8")

            if bcrypt.checkpw(entered_pw,stored_hashed_pw):
                print("✅ Password match")
                user_data = {"id":user.id, "email":user.email, "name":user.name}
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                response = JsonResponse({
                "message": "Verified successfully",
                "access": access_token,
                "refresh": str(refresh),
                "user": user_data
                })
                response.set_cookie(
                key="access",
                value=access_token,
                max_age=60 * 15,  # 15 minutes
                httponly=True,
                secure=False,     # True in production
                samesite="None"
                )
                response.set_cookie(
                key="refresh",
                value=str(refresh),
                max_age=60 * 60 * 24 * 7,  # 7 days
                httponly=True,
                secure=False,              # True in production
                samesite="None"
                )
                return response
                # jwt_payload = {
                #     "user_id": user.id,
                #     "email": user.email,
                # }
                # token = jwt.encode(jwt_payload, SECRET_KEY, algorithm="HS256")   
                # response = JsonResponse({"message":"Login successful","token":token,"user":user_data})
                # response.set_cookie(key='token',value=token,max_age=3600,httponly=True,secure=False,samesite='None')
                # return response
    # return response
            else:
                print("❌ Invalid password")
                return JsonResponse({"error": "Invalid email or password"}, status=400)
        except Exception as e:
            print("Login error:", e)
            return JsonResponse({"error": "Something went wrong"}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def logout(req):
    response = JsonResponse({'message': 'Logged out successfully'})
    response.delete_cookie('refresh')
    response.delete_cookie('access')
    return response
@csrf_exempt
def create_booking(req):
    booking_data = json.loads(req.body)
    serializer = BookingSSerializer(data=booking_data)
    if serializer.is_valid():
        serializer.save()
        return JsonResponse(serializer.data, status=status.HTTP_201_CREATED)
    return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def get_bookings(req): 
    bookings=Booking.objects.all()
    bookings_data=BookingSSerializer(bookings,many=True)
    print(bookings_data.data)
    return JsonResponse({"bookings":bookings_data.data})
# @api_view(["GET"])
# @permission_classes([IsAuthenticated])
def auth_check(request):
    try:
        token = request.COOKIES.get("access")
        print(token)
        if not token:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer"):
                token = auth_header.split(" ")[1]

        if not token:
            return JsonResponse({"auth": False}, status=401)
        validated = AccessToken(token)
        print(validated)
        user_id = validated["user_id"]
        print(user_id)
        user = User.objects.get(id=user_id)
        print(user)
        return JsonResponse({
            "auth":True,
            "user":{
                "id":user.id,
                "email":user.email,
                "name":user.name
            }
        })
    except Exception as e:
        return JsonResponse({"auth":False}, status=401)