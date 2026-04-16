from fastapi import APIRouter,HTTPException,Body,Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi import HTTPException
import os
from dotenv import load_dotenv
from fastapi import  HTTPException
from pydantic import BaseModel, EmailStr,validator
from pymongo import MongoClient
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os
from fastapi.responses import JSONResponse
from datetime import timedelta
from fastapi import  HTTPException
from typing import Optional
from bson import ObjectId


load_dotenv()


"""" custom module import """
from functions import generate_recovery_code,generate_token,send_recovery_email,send_verify_email_code
from jwt_dacorator import token_required







user_auth = APIRouter()




## set mongo client
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client['db_name']
user_collection = db['user_collection_name']
recovery_collection = db['recovery_code_collection_name']




""" data validation using pydantic """

class User(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str


class Login(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    token: str
    token_timestamp: datetime

class Mail_verify(BaseModel):
    email: EmailStr
    code : str

class Mail_verify_to_update(BaseModel):
    email: EmailStr
    code : str
    userid : str

class ForgotPassword(BaseModel):
    email: EmailStr

class Recovery(BaseModel):
    code: str

class ResetPassword(BaseModel):
    email: EmailStr
    code: str
    new_password: str
    confirm_password: str

class GetProfile(BaseModel):
    userid: str


class UpdateProfile(BaseModel):
    userid : str
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None
    confirm_password: Optional[str] = None
    profile_picture: Optional[str] = None  # Base64 encoded picture


"""  routers  """




@user_auth.post("/signup")
async def signup(user: User):
        if user_collection.find_one({"email": user.email}):
            raise HTTPException(status_code=409, detail="Email already in use. Please use a different email address.")

        hashed_password = CryptContext(schemes=["pbkdf2_sha256"]).hash(user.password)
        user_dict = user.dict()
        user_dict["password_hashed"] = hashed_password
        del user_dict["confirm_password"]    #original password ka kiya seen ha
        code= generate_recovery_code()
        response=send_verify_email_code(user.email, code)
        print(" repnse after mail  : ",response)
        if response=="success":
            user_collection.insert_one(user_dict)
            check_user_existance=user_collection.find_one({'email': user.email})
            db.verify_user_email.insert_one({"email":user.email,"code":code})
            return {"Response": "User created successfully","id":str(check_user_existance["_id"]),"username":str(check_user_existance['username'])}
        else:
            return {"Response": "mail server error occur"}






@user_auth.post("/verify_user_email")
async def verify_recovery_code(verify:Mail_verify):
    recovery_data = db.verify_user_email.find_one({
        "email":verify.email,
        "code":verify.code
    })
    print("recovery data   :  ",recovery_data)
    if not recovery_data:
        raise HTTPException(status_code=400, detail="Invalid or expired recovery code")

    if recovery_data:
        for labels in recovery_data:
                      if labels=="email" :
                          email=recovery_data[labels]
                      elif labels=="code":
                          code=recovery_data[labels]

        else:
            check_user_existance=user_collection.find_one({'email': verify.email})
            if email==verify.email and code==verify.code:
                filter_query = {"email": verify.email}
                result = db.verify_user_email.delete_one(filter_query)
                return {"message": "User created successfully","id":str(check_user_existance["_id"])}
            else:
                filter_query = {"email": verify.email}
                result = user_collection.delete_one(filter_query)
                if result.deleted_count > 0:
                    return {"message": "User not created successfully (may be code not match)"}
                else:

                    return {"message": "User not created successfully (may be code not match) "}




@user_auth.post("/login")
async def login(login_data: Login):
    user = user_collection.find_one({"email": login_data.email})

    if not user or not CryptContext(schemes=["pbkdf2_sha256"]).verify(login_data.password, user["password_hashed"]):
        print("user not found  : ")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Fetch the username from the user object
    username = user.get("username", "")
    print("username   : ",username)

    token = generate_token(login_data.email)
    print("token   : ",token )
    token_timestamp = datetime.utcnow() + timedelta(days=30)
    user_collection.update_one({"_id": user["_id"]}, {"$set": {"token": token, "token_timestamp": token_timestamp}})

    # Return the username along with the token and token timestamp
    return {"userid" : str(user["_id"]), "username": username, "token": token, "token_timestamp": token_timestamp}


@user_auth.post("/forgot_password")
async def forgot_password( forgot_password_data: ForgotPassword):
    user = user_collection.find_one({"email": forgot_password_data.email})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    code = generate_recovery_code()
    recovery_data = {
        "user_id": user["_id"],
        "recovery_code": code,
        "timestamp": datetime.utcnow()
    }
    db.recovery_collection.insert_one(recovery_data)

    send_recovery_email(forgot_password_data.email, code)
    return {"message": "Recovery code sent to your email"}

@user_auth.post("/verify_recovery_code")
async def verify_recovery_code(recovery: Recovery):
    recovery_data = db.recovery_collection.find_one({
        "recovery_code": recovery.code,
        "timestamp": {"$gte": datetime.utcnow() - timedelta(minutes=10)}
    })
    if not recovery_data:
        raise HTTPException(status_code=400, detail="Invalid or expired recovery code")
    return {"message": "Recovery code verified successfully"}

@user_auth.post("/reset_password")
async def reset_password(reset_password_data: ResetPassword):
    user = user_collection.find_one({"email": reset_password_data.email})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    recovery_data = db.recovery_collection.find_one({"recovery_code": reset_password_data.code})
    if not recovery_data:
        raise HTTPException(status_code=400, detail="Invalid or expired recovery code")

    expiration_time = recovery_data["timestamp"] + timedelta(minutes=10)
    if datetime.utcnow() > expiration_time:
        raise HTTPException(status_code=400, detail="Invalid or expired recovery code")

    if reset_password_data.new_password != reset_password_data.confirm_password:
        raise HTTPException(status_code=400, detail="New password and confirm password do not match")

    hashed_password = CryptContext(schemes=["pbkdf2_sha256"]).hash(reset_password_data.new_password)
    user_collection.update_one({"_id": user["_id"]}, {"$set": {"password_hashed": hashed_password, "plain_password": reset_password_data.new_password}})
    db.recovery_collection.delete_one({"_id": recovery_data["_id"]})

    return {"message": "Password successfully reset. You can now log in with your new password."}



@user_auth.post("/verify_user_email_to_update")
async def verify_email_code_to_update(verify:Mail_verify_to_update):
    data = verify.dict()
    print("dat   :  ",data)
    recovery_data = db.verify_user_email_update.find_one({
        "new_email":verify.email,
        "code":verify.code
    })
    print("recovery data   :  ",recovery_data)
    if not recovery_data:
        raise HTTPException(status_code=400, detail="Invalid recovery code")
    update_email= ""
    code = ""
    if recovery_data:
        for labels in recovery_data:
            if labels=="new_email" :
                update_email=recovery_data[labels]
            elif labels=="code":
                code =recovery_data[labels]
    if verify.email == update_email and verify.code==code:
        user_collection.update_one({"_id": ObjectId(verify.userid)}, {"$set": {"email": verify.email}})
        return JSONResponse(content="updated",status_code=200)
    else:
        return JSONResponse(content="Some error",status_code=400)



@user_auth.post("/update_profile")
async def update_profile(profile_data: UpdateProfile):
    user_id = profile_data.userid
    new_profile_picture=new_name=new_email=new_password=confirm_password=current_password=None
    if not user_id:
        raise HTTPException(status_code=404, detail="UserId Required")
    if profile_data.profile_picture is not None:
        new_profile_picture = profile_data.profile_picture
    if profile_data.name is not None:
        new_name = profile_data.name
    if profile_data.email is not None:
        new_email = profile_data.email
    if (profile_data.current_password is not None and
        profile_data.new_password is not None and
        profile_data.confirm_password is not None):

        current_password = profile_data.current_password
        new_password = profile_data.new_password
        confirm_password = profile_data.confirm_password
    user = user_collection.find_one({"_id": ObjectId(user_id)})
    new_data = {}
    if user:
        if new_profile_picture:
            new_data['profile_pic'] = new_profile_picture
        if new_name:
            new_data['username'] = new_name
        if new_email :
            # new_data['email'] = new_email
            code= generate_recovery_code()
            response=send_verify_email_code(new_email, code)
            if response=="success":
                db.verify_user_email_update.insert_one({"userid" :profile_data.userid , "new_email": new_email, "code": code})
                return JSONResponse(content="Email sent",status_code=200)
            else:
                return JSONResponse(content="Email not sent",status_code=500)
        if current_password :
            if current_password == user['password']:
                if new_password==confirm_password:
                    new_data['password'] = new_password
                    hashed_password = CryptContext(schemes=["pbkdf2_sha256"]).hash(new_password)
                    new_data['password_hashed'] = hashed_password
                else:
                    return JSONResponse(content = "new password and confirmed password not matched",status_code=400)
            else:
                return JSONResponse(content = "Current password not correct",status_code=400)
        if new_data:
            user_collection.update_one({"_id": ObjectId(user_id)}, {"$set": new_data})
            return JSONResponse(content = "updated ", status_code=200)
        else:
            return JSONResponse(content = "Empty payload ", status_code=200)
    else:
        raise HTTPException(status_code=404, detail="User not found")

@user_auth.get("/get_profile")
async def get_profile(user_id : str ):
    # user_id = get_profile_data.userid
    if not user_id:
        raise HTTPException(status_code=404, detail="UserId Required")

    user = user_collection.find_one({"_id": ObjectId(user_id)})
    if user:
        pic = user.get("profile_pic",None)
        name = user.get("username",None)
        if name :
            content = {"username":name,"picture":pic}
            return JSONResponse(content = content, status_code=200)
        else:
            return JSONResponse(content = "No profile image ", status_code=401)
    else:
        raise HTTPException(status_code=404, detail="User not found")




















