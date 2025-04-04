# Authentication MicroService

A Django-based microservice for user authentication, including:

- Email verification on registration
- Login with password or OTP (Twilio)
- Password reset via email
- Role-based dashboards (Admin/User)
- JWT Authentication
- Celery & Redis for async tasks

---


## Clone the Repository
### Set Up Virtual EnvironmentRepository

```bash
python -m venv .venv
.venv\Scripts\activate 
```
### Install Project Requirements
 ```bash
pip install -r requirements.txt
 ```

### Environment Variables
```bash
EMAIL_HOST_USER=""
EMAIL_HOST_PASSWORD=""
HOST_URL="http://localhost:8000"

TWILIO_ACCOUNT_SID=""
TWILIO_AUTH_TOKEN=""
TWILIO_PHONE_NUMBER=""
 ```


### Run Database Migrations

 ```bash
 python manage.py makemigrations
 python manage.py migrate
 ```

### Create Superuser (Admin)

  ```bash
    python manage.py createsuperuser
  ```

## Running the Application
### Start Django Server

  ```bash
    python manage.py runserver
  ```

### Start Redis Server (Required for Celery =>in WSL)
  ```bash     
         sudo service redis-server start
         redis-server

  ```
###  Start Celery Worker
  ```bash     
        celery -A Authentication_microService worker --loglevel=info
  ```