# import random 
# from django.core.mail import send_mail
# from .models import OTP
# import resend
# from django.conf import settings

# def generate_and_send_otp(user_email):
#     code = f"{random.randint(100000, 999999):06d}"
#     print(type(code))
#     # send_mail(
#     #     subject='Your signup OTP',
#     #     message=f'Your OTP is {code}. It expires in 5 minutes.',
#     #     from_email='vineethnalla12@gmail.com',
#     #     recipient_list=[user_email]
#     # )
#     resend.api_key = f"{settings.RENDER_KEY}"

#     r = resend.Emails.send({
#             "from": "YourApp <onboarding@resend.dev>",
#             "to": [user_email],
#             "subject": "Your OTP",
#             "html": f"<p>Your OTP is <b>{code}</b></p>",
#            })
    return code
