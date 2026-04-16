from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from functools import wraps
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from functions import JWT_SECRET_KEY


async def token_required(f):
    @wraps(f)
    async def decorated(request: Request):
        token = request.headers.get('x-access-token')
        print("token from header  : ",token)

        if not token:
            content = {'Response': 'Token is missing!'}
            raise HTTPException(status_code=401, detail=content)
        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256']) 
            print("token data  :  ", data)

        except ExpiredSignatureError:
            content = {'Error': 'Token has expired!'}
            raise HTTPException(status_code=401, detail=content)

        except InvalidTokenError as e:
            content = {'Error': f'Token is invalid: {str(e)}'}
            raise HTTPException(status_code=401, detail=content)

        return await f(request)

    return decorated


