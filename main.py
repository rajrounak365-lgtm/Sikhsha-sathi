import bcrypt
import datetime
import io
import os
import random
import smtplib
import string
import uuid
import zipfile
from email.mime.text import MIMEText
from typing import Optional, List
from authlib.integrations.starlette_client import OAuth
from bson import ObjectId
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, HTTPException, Query, UploadFile, File, Response
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pymongo import MongoClient
from starlette.middleware.sessions import SessionMiddleware
from gridfs import GridFS

# --------------------------
# Load environment variables
# --------------------------
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret")
MONGODB_URI = os.getenv("MONGODB_URI")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")

# --------------------------
# FastAPI App Setup
# --------------------------
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)  # type: ignore
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# --------------------------
# MongoDB Setup
# --------------------------
mongo_client = MongoClient(MONGODB_URI)
db = mongo_client["user_auth"]  # this will use your "sikhsha_sathi"
users_collection = db["users"]
institutes_collection = db["institutes"]
fs=GridFS(db,collection="materials_files")

# --------------------------
# Google OAuth Setup
# --------------------------
oauth = OAuth()
oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


# --------------------------
# Helpers
# --------------------------
def generate_strong_password(length=10):
    """Generate a random strong password."""
    while True:
        password = ''.join(random.choices(
            string.ascii_uppercase + string.ascii_lowercase + string.digits + "!@#$&", k=length
        ))
        if (any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in "!@#$&" for c in password)):
            return password


def send_email(to_email: str, new_password: str):
    message = MIMEText(f"""
Dear User,

You recently requested to reset your password for your Sikhsha Sathi account.

Here is your new temporary password:

>>> {new_password} <<<

Please use this password to log in to your account. Once logged in, we strongly recommend changing it immediately for 
security reasons.

If you did not request a password reset, please ignore this email or contact our support team.

Regards,
Sikhsha Sathi Team
""", "plain")

    message['Subject'] = 'Your Forgot Password - Sikhsha Sathi'
    message['From'] = SENDER_EMAIL
    message['To'] = to_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_email, message.as_string())


# --------------------------
# ROUTE 1: Home / Index Page
# --------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """
    Entry page. If user is already logged in (session exists),
    redirect them to their dashboard based on role.
    Otherwise, show index.html for login/signup.
    """
    user = request.session.get("user")

    if user:
        # Already logged in → check role
        if user["role"] == "platform_admin":
            return RedirectResponse("/admin-dashboard", status_code=302)
        elif user["role"] == "institute_admin":
            if not user.get("profile_complete", False):
                return RedirectResponse("/complete-profile", status_code=302)
            return RedirectResponse("/institute-dashboard", status_code=302)

    # Not logged in → show index page
    return templates.TemplateResponse("index.html", {"request": request})


# --------------------------
# ROUTE 2: Manual Signup
# --------------------------
@app.get("/signup", response_class=HTMLResponse)
async def get_signup(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/signup", response_class=HTMLResponse)
async def signup_user(
        request: Request,
        role: str = Form(...),  # "platform_admin" OR "institute_admin"
        name: str = Form(...),
        email: str = Form(...),
        password: str = Form(...)
):
    """
    Manual signup for Admin or Institute.
    - Admin → redirect to Admin Dashboard
    - Institute → redirect to Complete Profile
    """
    # Restrict platform_admin to max 2 users
    if role == "platform_admin":
        count_admins = users_collection.count_documents({"role": "platform_admin"})
        if count_admins >= 2:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "error": "Signup blocked: Only platform admins are allowed to access!"
            })

    # Check if user already exists
    if users_collection.find_one({"email": email}):
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "User already exists!"
        })

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # Insert new user
    new_user = {
        "name": name,
        "email": email,
        "password": hashed_password,
        "auth_type": "manual",
        "role": role,
        "profile_complete": False,
        "created_at": datetime.datetime.now(datetime.timezone.utc)
    }
    users_collection.insert_one(new_user)

    # Save session
    request.session["user"] = {
        "name": name,
        "email": email,
        "role": role,
        "profile_complete": False
    }

    # Redirect based on role
    if role == "platform_admin":
        return RedirectResponse("/admin-dashboard", status_code=302)
    else:  # institute_admin
        return RedirectResponse("/complete-profile", status_code=302)


# --------------------------
# ROUTE 3: Complete Profile (Institute Only)
# --------------------------

@app.get("/complete-profile", response_class=HTMLResponse)
async def complete_profile_form(request: Request):
    """
    Show profile completion form for institute admins.
    If user is not logged in OR not an institute admin → redirect to home.
    """
    user = request.session.get("user")

    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)

    if user.get("profile_complete", False):
        return RedirectResponse("/institute-dashboard", status_code=302)

    return templates.TemplateResponse("complete_profile.html", {"request": request})


@app.post("/complete-profile", response_class=HTMLResponse)
async def complete_profile(
        request: Request,
        institute_name: str = Form(...),
        institute_address: str = Form(...),
        institute_phone: str = Form(...),
        institute_email: str = Form(...),
        owner_phone: str = Form(...)
):
    """
    Save institute profile details, mark profile as complete,
    then redirect to institute dashboard.
    """
    user = request.session.get("user")
    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)

    # Save institute details
    institutes_collection.insert_one({
        "institute_name": institute_name,
        "address": institute_address,
        "phone": institute_phone,
        "email": institute_email,
        "owner_phone": owner_phone,
        "created_at": datetime.datetime.now(datetime.timezone.utc),
        "user_email": user["email"]
    })

    # Mark user profile complete in DB
    users_collection.update_one(
        {"email": user["email"]},
        {"$set": {"profile_complete": True}}
    )

    # Update session too
    request.session["user"]["profile_complete"] = True

    return RedirectResponse("/institute-dashboard", status_code=302)


# --------------------------
# ROUTE 4: Manual Login
# --------------------------
# Render login page
@app.get("/login-manual", response_class=HTMLResponse)
async def show_login_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/login-manual", response_class=HTMLResponse)
async def login_manual(request: Request, email: str = Form(...), password: str = Form(...), role: str = Form(...)):
    """
    Manual login with email + password (for 'manual' auth_type users).
    Redirects to dashboard or complete-profile depending on status.
    """

    # 1. Find user by email
    user = users_collection.find_one({"email": email, "auth_type": "manual", "role": role})

    if not user:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "No manual account found with this email."
        })

    # 2. Verify password
    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "Invalid email or password."
        })

    # Restrict platform_admin login if limit reached
    if user["role"] == "platform_admin":
        allowed_admins = list(users_collection.find({"role": "platform_admin"}).limit(2))
        allowed_emails = [u["email"] for u in allowed_admins]
        if user["email"] not in allowed_emails:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "error": "Access denied: Only platform admins allowed to access."
            })

    # 3. Save session
    request.session["user"] = {
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "profile_complete": user.get("profile_complete", False)
    }

    # 4. Redirect based on role + profile status
    if user["role"] == "platform_admin":
        return RedirectResponse("/admin-dashboard", status_code=302)
    elif user["role"] == "institute_admin":
        if not user.get("profile_complete", False):
            return RedirectResponse("/complete-profile", status_code=302)
        return RedirectResponse("/institute-dashboard", status_code=302)

    return RedirectResponse("/", status_code=302)


# --------------------------
# ROUTE 5: Google Login
# --------------------------

@app.get("/login")
async def login_google(request: Request):
    """
    Start Google OAuth login.
    """
    return await oauth.google.authorize_redirect(request, REDIRECT_URI)


@app.get("/auth/callback")
async def auth_callback(request: Request):
    """
    Handle Google OAuth callback.
    Restrict platform_admins to max 2 users.
    """
    token = await oauth.google.authorize_access_token(request)
    user_info = token["userinfo"]

    email = user_info["email"]
    name = user_info["name"]

    # ✅ Check if user exists by email (not only google)
    user = users_collection.find_one({"email": email})

    if user:
        # ✅ Upgrade auth_type to include google if not already
        if isinstance(user.get("auth_type"), str):
            auth_types = [user["auth_type"]]
        else:
            auth_types = user.get("auth_type", [])

        if "google" not in auth_types:
            users_collection.update_one(
                {"_id": user["_id"]},
                {"$set": {"auth_type": auth_types + ["google"]}}
            )
            user["auth_type"] = auth_types + ["google"]

    else:
        # New Google signup → default role = institute_admin
        new_user = {
            "name": name,
            "email": email,
            "auth_type": ["google"],  # store as list for flexibility
            "role": "institute_admin",
            "profile_complete": False,
            "created_at": datetime.datetime.now(datetime.timezone.utc)
        }

        # Restrict platform_admin creation if limit reached
        if new_user["role"] == "platform_admin":
            count_admins = users_collection.count_documents({"role": "platform_admin"})
            if count_admins >= 2:
                return templates.TemplateResponse("index.html", {
                    "request": request,
                    "error": "Signup blocked: Only 2 platform admins are allowed!"
                })

        users_collection.insert_one(new_user)
        user = new_user

    # Restrict platform_admin logins if more than 2 exist
    if user["role"] == "platform_admin":
        allowed_admins = list(users_collection.find({"role": "platform_admin"}).limit(2))
        allowed_emails = [u["email"] for u in allowed_admins]
        if user["email"] not in allowed_emails:
            return templates.TemplateResponse("index.html", {
                "request": request,
                "error": "Access denied: Only 2 platform admins allowed."
            })

    # Save session
    request.session["user"] = {
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "profile_complete": user.get("profile_complete", False)
    }

    # Redirect based on role
    if user["role"] == "platform_admin":
        return RedirectResponse("/admin-dashboard", status_code=302)
    elif user["role"] == "institute_admin":
        if not user.get("profile_complete", False):
            return RedirectResponse("/complete-profile", status_code=302)
        return RedirectResponse("/institute-dashboard", status_code=302)

    return RedirectResponse("/", status_code=302)


# --------------------------
# Route 6: Forgot Password for both
# --------------------------
@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request})


@app.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password(request: Request, email: str = Form(...)):
    """
    Forgot password for manual accounts only.
    Generates a new strong password, updates DB,
    and sends it via email.
    """
    user = users_collection.find_one({"email": email, "auth_type": "manual"})
    if not user:
        return templates.TemplateResponse("forgot_password.html", {
            "request": request,
            "error": "No manual account found with this email."
        })

    # Generate new password
    new_password = generate_strong_password()
    hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

    # Update in DB
    users_collection.update_one(
        {"email": email},
        {"$set": {"password": hashed_password}}
    )

    # Send email
    send_email(email, new_password)

    return templates.TemplateResponse("forgot_password.html", {
        "request": request,
        "message": "A new password has been sent to your email."
    })


# # --------------------------
# # ROUTE 7: Admin Dashboard
# # --------------------------
# @app.get("/admin-dashboard", response_class=HTMLResponse)
# async def admin_dashboard(request: Request):
#     user = request.session.get("user")
#     if not user or user["role"] != "platform_admin":
#         return RedirectResponse("/", status_code=302)
#
#     # Example analytics (later replace with real data)
#     total_institutes = institutes_collection.count_documents({})
#     total_users = users_collection.count_documents({"role": "institute_admin"})
#
#     return templates.TemplateResponse("admin_dashboard.html", {
#         "request": request,
#         "user": user,
#         "total_institutes": total_institutes,
#         "total_users": total_users
#     })


# ----------------------------
# ROUTE 8: Institute Dashboard
# ------------------------------

@app.get("/institute-dashboard", response_class=HTMLResponse)
async def institute_dashboard(request: Request):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    institute_id = str(institute["_id"])

    # ---- Dashboard Counts ----
    total_students = db["students"].count_documents({
        "institute_id": institute_id, "status": "Active"
    })
    active_faculty = db["faculties"].count_documents({
        "institute_id": institute_id
    })
    running_courses = db["courses"].count_documents({
        "institute_id": institute_id, "status": "Active"
    })

    # Monthly revenue (current month only)
    start_month = datetime.datetime(datetime.datetime.now().year, datetime.datetime.now().month, 1)
    monthly_revenue = db["payments"].aggregate([
        {"$match": {
            "institute_id": institute_id,
            "date": {"$gte": start_month}
        }},
        {"$group": {"_id": None, "total": {"$sum": {"$toDouble": "$amount"}}}}
    ])
    monthly_revenue = next(monthly_revenue, {}).get("total", 0)

    # Recent activities (latest 5 from students, payments, tests, materials)
    recent_activities = []
    recent_activities.extend(list(db["students"].find(
        {"institute_id": institute_id, "status": "Active"}
    ).sort("joined_date", -1).limit(2)))

    recent_activities.extend(list(db["payments"].find(
        {"institute_id": institute_id}
    ).sort("date", -1).limit(2)))

    recent_activities.extend(list(db["tests"].find(
        {"institute_id": institute_id, "status": "Scheduled"}
    ).sort("created_at", -1).limit(1)))

    recent_activities.extend(list(db["materials"].find(
        {"institute_id": institute_id}
    ).sort("created_at", -1).limit(1)))

    # Upcoming Events (next 5 active events)
    upcoming_events = list(db["events"].find(
        {"institute_id": institute_id, "status": "Active", "date": {"$gte": datetime.datetime.now()}}
    ).sort("date", 1).limit(5))

    # Fetch all active students once
    students_list = list(db["students"].find({"institute_id": institute_id, "status": "Active"}))

    return templates.TemplateResponse("institute_dashboard.html", {
        "request": request,
        "user": user,
        "institute": institute,
        "total_students": total_students,
        "active_faculty": active_faculty,
        "running_courses": running_courses,
        "monthly_revenue": monthly_revenue,
        "recent_activities": recent_activities,
        "upcoming_events": upcoming_events,
        "students_list": students_list  # <-- pass this
    })


# --------------------------
# ROUTE 9: Events
# --------------------------

@app.get("/events", response_class=HTMLResponse)
async def list_events(request: Request):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    institute_id = str(institute["_id"])
    events = list(db["events"].find({"institute_id": institute_id}).sort("date", 1))

    return templates.TemplateResponse("all_events.html", {
        "request": request,
        "events": events
    })


@app.get("/event/add", response_class=HTMLResponse)
async def add_event_page(request: Request):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("add_event.html", {"request": request})


@app.post("/event/add")
async def add_event(
        request: Request,
        title: str = Form(...),
        description: str = Form(""),
        date: str = Form(...),
        hour: str = Form(...),
        minute: str = Form(...),
        ampm: str = Form(...),
        audience: str = Form(...),
        event_type: str = Form(...)
):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    # Combine hour, minute, am/pm into a time string
    time = f"{hour}:{minute} {ampm}"

    event_doc = {
        "institute_id": str(institute["_id"]),
        "title": title,
        "description": description,
        "date": datetime.datetime.strptime(date, "%Y-%m-%d"),
        "time": time,
        "audience": audience,
        "type": event_type,
        "status": "Active",
        "created_at": datetime.datetime.now(),
        "updated_at": datetime.datetime.now()
    }
    db["events"].insert_one(event_doc)

    return RedirectResponse("/institute-dashboard", status_code=302)


@app.post("/event/delete/{event_id}")
async def delete_event(event_id: str, request: Request):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    db["events"].delete_one({"_id": ObjectId(event_id)})
    return RedirectResponse("/institute-dashboard", status_code=302)


# --------------------------
# ROUTE 10: Logout
# --------------------------
@app.get("/logout")
async def logout(request: Request):
    """
    Clear session and redirect to home page.
    """
    request.session.pop("user", None)
    return RedirectResponse("/", status_code=302)


# --------------------------
# ROUTE 11: Setting Page
# --------------------------

# GET: Institute Settings Page
@app.get("/settings", response_class=HTMLResponse)
async def institute_settings(request: Request):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    # Fetch institute data
    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    return templates.TemplateResponse("settings.html", {
        "request": request,
        "institute": institute,
        "user": user
    })


# POST: Update Institute Settings
@app.post("/settings")
async def update_settings(
        request: Request,
        institute_name: str = Form(...),
        contact_email: str = Form(...),
        contact_phone: str = Form(...),
        address: str = Form(...),
        new_password: str = Form(None)  # optional password field
):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    # Update institute info
    institutes_collection.update_one(
        {"user_email": user["email"]},
        {"$set": {
            "institute_name": institute_name,
            "email": contact_email,
            "owner_phone": contact_phone,
            "address": address,
            "updated_at": datetime.datetime.now()
        }}
    )

    # Handle password update for manual auth users
    if new_password and "manual" in user.get("auth_type", []):
        import bcrypt
        hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        users_collection.update_one(
            {"email": user["email"]},
            {"$set": {"password": hashed_pw}}
        )

    return RedirectResponse("/settings", status_code=302)


# --------------------------
# ROUTE 12: Students
# --------------------------
@app.get("/students", response_class=HTMLResponse)
async def list_students(request: Request):
    user = request.session.get("user")
    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        return templates.TemplateResponse("students.html", {
            "request": request,
            "error": "No institute profile found!"
        })

    # Base query
    query = {"institute_id": str(institute["_id"])}
    and_conditions = [query]

    # Filters
    search = request.query_params.get("search")
    course = request.query_params.get("course")
    status = request.query_params.get("status")
    payment_status = request.query_params.get("payment_status")

    if search:
        and_conditions.append({
            "$or": [
                {"name": {"$regex": search, "$options": "i"}},
                {"phone": {"$regex": search, "$options": "i"}}
            ]
        })
    if course:
        and_conditions.append({"course": course})
    if status:
        and_conditions.append({"status": status})
    if payment_status:
        and_conditions.append({"payment_status": payment_status})

    final_query = {"$and": and_conditions}

    students = list(db["students"].find(final_query))
    for s in students:
        s["_id"] = str(s["_id"])

    # Get all courses of this institute (for dropdown in add-student form)
    courses = list(db["courses"].find({"institute_id": str(institute["_id"])}))
    for c in courses:
        c["_id"] = str(c["_id"])

    # Prepare names for filter dropdown
    course_names = [c["name"] for c in courses]

    # In template, pass courses with _id for form select, and names for filter
    return templates.TemplateResponse("students.html", {
        "request": request,
        "students": students,
        "institute": institute,
        "courses": courses,  # for dropdown to select _id
        "course_names": course_names  # for filter dropdown
    })


@app.post("/students/add")
async def add_student(
        request: Request,
        name: str = Form(...),
        phone: str = Form(...),
        student_email: str = Form(...),
        course_id: str = Form(...),  # <-- changed from course name to course_id
        joined_date: str = Form(...),
        guardian_name: str = Form(...),
        guardian_phone: str = Form(...),
        village: str = Form(...),
        status: str = Form("Active")
):
    user = request.session.get("user")
    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    # Get course by ID
    course_doc = db["courses"].find_one({
        "_id": ObjectId(course_id),
        "institute_id": str(institute["_id"])
    })
    if not course_doc:
        raise HTTPException(status_code=400, detail="Selected course not found")

    # Insert student with course_id
    db["students"].insert_one({
        "name": name,
        "phone": phone,
        "course_id": str(course_doc["_id"]),
        "course_name": course_doc["name"],
        "student_email": student_email,
        "joined_date": joined_date,
        "guardian_name": guardian_name,
        "guardian_phone": guardian_phone,
        "village": village,
        "status": status,
        "payment_status": "Pending",
        "institute_id": str(institute["_id"]),
        "institute_email": user["email"]
    })

    return RedirectResponse("/students", status_code=302)


@app.get("/students/{student_id}", response_class=HTMLResponse)
async def view_student(request: Request, student_id: str):
    """
    View a single student's profile (for the current institute).
    """
    user = request.session.get("user")
    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)

    # Get institute
    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    # Find student linked to this institute
    student = db["students"].find_one({
        "_id": ObjectId(student_id),
        "institute_id": str(institute["_id"])
    })
    courses = list(db["courses"].find({"institute_id": str(institute["_id"])}))
    for c in courses:
        c["_id"] = str(c["_id"])

    if not student:
        raise HTTPException(status_code=404, detail="Student not found")

    student["_id"] = str(student["_id"])

    return templates.TemplateResponse("student_profile.html", {
        "request": request,
        "student": student,
        "institute": institute,
        "courses": courses
    })


@app.post("/students/update/{student_id}")
async def update_student(
        request: Request,
        student_id: str,
        name: str = Form(...),
        phone: str = Form(...),
        student_email: str = Form(...),
        course_id: str = Form(...),
        joined_date: str = Form(...),
        guardian_name: str = Form(...),
        guardian_phone: str = Form(...),
        village: str = Form(...),
        status: str = Form(...),
        payment_status: str = Form(...)
):
    """
    Update student details (only for the current institute).
    """
    user = request.session.get("user")
    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)

    # Get the current institute
    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")
    # Get the course document by ID
    course_doc = db["courses"].find_one({
        "_id": ObjectId(course_id),
        "institute_id": str(institute["_id"])
    })
    if not course_doc:
        raise HTTPException(status_code=400, detail="Selected course not found")

    # Update student
    result = db["students"].update_one(
        {"_id": ObjectId(student_id), "institute_id": str(institute["_id"])},
        {"$set": {
            "name": name,
            "phone": phone,
            "student_email": student_email,
            "course_id": str(course_doc["_id"]),
            "course_name": course_doc["name"],
            "joined_date": joined_date,
            "guardian_name": guardian_name,
            "guardian_phone": guardian_phone,
            "village": village,
            "status": status,
            "payment_status": payment_status
        }}
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Student not found or not updated")

    return RedirectResponse(f"/students/{student_id}", status_code=302)


@app.post("/students/delete/{student_id}")
async def delete_student(request: Request, student_id: str):
    """
    Delete a student (only from the logged-in institute)
    and all their payment records.
    """
    user = request.session.get("user")
    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    # Delete student only if belongs to this institute
    result = db["students"].delete_one({
        "_id": ObjectId(student_id),
        "institute_id": str(institute["_id"])
    })

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Student not found")

    # Also delete all payments for this student
    db["payments"].delete_many({"student_id": student_id})

    return RedirectResponse("/students", status_code=302)


# --------------------------
# ROUTE 13: Faculty
# --------------------------

@app.get("/faculty", response_class=HTMLResponse)
async def list_faculty(request: Request):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    # find institute for this admin
    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        return templates.TemplateResponse("faculty.html", {
            "request": request,
            "error": "No institute profile found!"
        })

    # base filter: only this institute's faculty
    base_condition = {"institute_id": str(institute["_id"])}

    # query params from the form / URL
    search = request.query_params.get("search")  # text search (name, phone, email)
    subject = request.query_params.get("subject")  # subject filter (matches element in subjects array)
    status = request.query_params.get("status")  # Active / Inactive

    # build an $and list so all conditions are combined
    and_conditions = [base_condition]

    if search:
        and_conditions.append({
            "$or": [
                {"name": {"$regex": search, "$options": "i"}},
                {"phone": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}}
            ]
        })

    if subject:
        # subjects stored as array -> match if the subject is present in the array
        and_conditions.append({"subjects": subject})

    if status:
        and_conditions.append({"status": status})

    # final query: if only base_condition exists, use it directly; otherwise use $and
    if len(and_conditions) == 1:
        final_query = and_conditions[0]
    else:
        final_query = {"$and": and_conditions}

    # fetch from DB and convert ObjectId to str for templates
    faculties = list(db["faculties"].find(final_query))
    for f in faculties:
        f["_id"] = str(f["_id"])

    # distinct subjects to populate subject filter dropdown
    subjects = db["faculties"].distinct("subjects", {"institute_id": str(institute["_id"])})

    # Get all courses of this institute (for dropdown in add-student form)
    courses = list(db["courses"].find({"institute_id": str(institute["_id"])}))
    for c in courses:
        c["_id"] = str(c["_id"])

    # Prepare names for filter dropdown
    course_names = [c["name"] for c in courses]

    return templates.TemplateResponse("faculty.html", {
        "request": request,
        "faculties": faculties,
        "institute": institute,
        "subjects": subjects,
        "courses": courses,
        "courses_names": course_names
    })


@app.post("/faculty/add")
async def add_faculty(
        request: Request,
        name: str = Form(...),
        email: str = Form(...),
        phone: str = Form(...),
        subjects: str = Form(...),  # comma-separated subjects
        qualification: str = Form(...),
        experience: str = Form(...),
        monthly_salary: str = Form(...),
        batch: Optional[List[str]] = Form(None),  # multiple selected batch IDs
        address: str = Form(""),
        joining_date: str = Form(None)
):
    """
    Add a new faculty member for the logged-in institute.
    Supports multiple batches and multiple subjects.
    """
    # Authentication check
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    #  Get institute
    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    #  Subjects → list
    subject_list = [s.strip() for s in subjects.split(",") if s.strip()]

    #  Joining date default
    if not joining_date:
        joining_date = datetime.datetime.today().strftime("%Y-%m-%d")

    #  Convert batch IDs to ObjectId and fetch course names
    batch_names = []
    if batch:  # ✅ only loop if not None and not empty
        for fid in batch:
            course_doc = db["courses"].find_one({
                "_id": ObjectId(fid),
                "institute_id": str(institute["_id"])
            })
            if course_doc:
                batch_names.append(course_doc["name"])

    #  Prepare faculty document
    faculty_doc = {
        "institute_id": str(institute["_id"]),
        "name": name,
        "email": email,
        "phone": phone,
        "subjects": subject_list,
        "qualification": qualification,
        "experience": experience,
        "monthly_salary": monthly_salary,
        "batch": batch_names,  # store course names for display
        "address": address,
        "joining_date": joining_date,
        "created_at": datetime.datetime.now(datetime.timezone.utc)
    }

    #  Insert into DB
    db["faculties"].insert_one(faculty_doc)

    # Redirect to faculty list
    return RedirectResponse("/faculty", status_code=302)


@app.get("/faculty/{faculty_id}", response_class=HTMLResponse)
async def faculty_profile(request: Request, faculty_id: str):
    """
    Show profile details of a single faculty member.
    """
    user = request.session.get("user")
    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)
    # Get institute
    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    # Find Faculty linked to this institute

    faculty = db["faculties"].find_one({"_id": ObjectId(faculty_id),
                                        "institute_id": str(institute["_id"])})
    courses = list(db["courses"].find({"institute_id": str(institute["_id"])}))
    for c in courses:
        c["_id"] = str(c["_id"])
    if not faculty:
        return templates.TemplateResponse("faculty_profile.html", {
            "request": request,
            "error": "Faculty not found!"
        })

    # Convert ObjectId to string for frontend
    faculty["_id"] = str(faculty["_id"])

    return templates.TemplateResponse("faculty_profile.html", {
        "request": request,
        "faculty": faculty,
        "courses": courses
    })


@app.post("/faculty/update/{faculty_id}")
async def update_faculty(
        request: Request,
        faculty_id: str,
        name: str = Form(...),
        email: str = Form(...),
        phone: str = Form(...),
        qualification: str = Form(...),
        experience: str = Form(...),
        monthly_salary: str = Form(...),
        batch: Optional[list[str]] = Form(None),  # optional now
        subjects: str = Form(...),
        address: str = Form(...),
        joining_date: str = Form(...)
):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    # ❌ Validation check: any required field missing?
    error_msg = None
    if not name or not email or not phone or not qualification or not subjects or not batch:
        error_msg = "Please fill all required fields and select at least one batch."

    if error_msg:
        # Fetch courses for the form again
        courses = list(db["courses"].find({"institute_id": str(institute["_id"])}))
        for c in courses:
            c["_id"] = str(c["_id"])
        # Fetch current faculty details to refill the form
        faculty = db["faculties"].find_one({"_id": ObjectId(faculty_id), "institute_id": str(institute["_id"])})
        if faculty:
            faculty["_id"] = str(faculty["_id"])
        return templates.TemplateResponse("edit_faculty.html", {
            "request": request,
            "faculty": faculty,
            "courses": courses,
            "error": error_msg
        })

    # Convert batch IDs → course names
    batch_names = []
    for fid in batch:
        try:
            course_doc = db["courses"].find_one({
                "_id": ObjectId(fid),
                "institute_id": str(institute["_id"])
            })
            if course_doc:
                batch_names.append(course_doc["name"])
        except Exception:
            continue

    # Subjects list
    subject_list = [s.strip() for s in subjects.split(",") if s.strip()]

    update_data = {
        "name": name,
        "email": email,
        "phone": phone,
        "qualification": qualification,
        "experience": experience,
        "monthly_salary": monthly_salary,
        "batch": batch_names,
        "subjects": subject_list,
        "address": address,
        "joining_date": joining_date
    }

    db["faculties"].update_one(
        {"_id": ObjectId(faculty_id), "institute_id": str(institute["_id"])},
        {"$set": update_data}
    )

    return RedirectResponse("/faculty", status_code=302)


@app.post("/faculty/delete/{faculty_id}")
async def delete_course(request: Request, course_id: str):
    """
    Permanently delete a faculty by ID.
    """
    user = request.session.get("user")
    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)

    # Get the current institute
    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    result = db["faculties"].delete_one({"_id": ObjectId(course_id),
                                         "institute_id": str(institute["_id"])})

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Course not found")

    return RedirectResponse("/faculty", status_code=302)


# --------------------------
# ROUTE 14: Courses/Batch
# --------------------------


@app.get("/course", response_class=HTMLResponse)
async def list_courses(request: Request):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    # find institute for this admin
    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        return templates.TemplateResponse("courses.html", {
            "request": request,
            "courses": [],
            "error": "No institute profile found!"
        })

    # base filter: only this institute's courses
    base_condition = {"institute_id": str(institute["_id"])}

    # query params from the form / URL
    search = request.query_params.get("search")  # text search (name, desc)
    course_type = request.query_params.get("type")  # Competitive / Board / Foundation
    status = request.query_params.get("status")  # Active / Inactive

    # build an $and list so all conditions are combined
    and_conditions = [base_condition]

    if search:
        and_conditions.append({
            "$or": [
                {"name": {"$regex": search, "$options": "i"}},
                {"description": {"$regex": search, "$options": "i"}}
            ]
        })

    if course_type:
        and_conditions.append({"type": course_type})  # course_type → stored in "type"

    if status:
        and_conditions.append({"status": status})

    final_query = and_conditions[0] if len(and_conditions) == 1 else {"$and": and_conditions}

    # Fetch courses
    courses = list(db["courses"].find(final_query))
    for c in courses:
        c["_id"] = str(c["_id"])
        # Count enrolled students
        student_count = db["students"].count_documents({
            "course_id": str(c["_id"]),
            "institute_id": str(institute["_id"])
        })
        c["student_count"] = student_count
        # Optional: enrollment percentage if max_students is set
        max_students = c.get("max_students", 1)
        c["enrollment_percentage"] = round((student_count / max_students) * 100)

    # Distinct course types for filter dropdown
    course_types = db["courses"].distinct("type", {"institute_id": str(institute["_id"])})
    # Fetch faculties for this institute to populate dropdown
    faculties = list(db["faculties"].find({"institute_id": str(institute["_id"])}))
    for f in faculties:
        f["_id"] = str(f["_id"])

    return templates.TemplateResponse("courses.html", {
        "request": request,
        "courses": courses,
        "institute": institute,
        "course_types": course_types,
        "faculties": faculties  # ✅ added
    })


@app.post("/course/add")
async def add_courses(
        request: Request,
        name: str = Form(...),
        course_type: str = Form(...),
        assigned_faculty: Optional[list[str]] = Form(None),  # Faculty ObjectId from form
        duration: str = Form(...),
        fees: float = Form(...),
        monthly_installments: float = Form(...),
        max_students: int = Form(...),
        start_date: str = Form(...),
        schedule_time: str = Form(...),
        subjects: str = Form(...),
        description: str = Form(...),
        status: str = Form("Active")
):
    """
    Add a new course for the logged-in institute.
    """
    user = request.session.get("user")
    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        return templates.TemplateResponse("courses.html", {
            "request": request,
            "error": "No institute profile found!"
        })

    # Convert subjects string → list
    subject_list = [s.strip() for s in subjects.split(",") if s.strip()]

    # Convert start_date string → datetime
    try:
        start_date_obj = datetime.datetime.strptime(start_date, "%Y-%m-%d")
    except ValueError:
        start_date_obj = start_date  # fallback to string if format is wrong

    # assigned_faculty now is a list of strings from form
    if isinstance(assigned_faculty, str):
        # only one selected
        assigned_faculty_ids = [ObjectId(assigned_faculty)]
    else:
        # multiple selected
        assigned_faculty_ids = [ObjectId(fid) for fid in assigned_faculty]

    # You can store in your course document as a list
    course_data = {
        "institute_id": str(institute["_id"]),
        "name": name,
        "type": course_type,
        "duration": duration,
        "fee": fees,
        "monthly_installments": monthly_installments,
        "max_students": max_students,
        "start_date": start_date_obj,
        "schedule_time": schedule_time,
        "subjects": subject_list,
        "description": description,
        "status": status,
        "assigned_faculty": [str(fid) for fid in assigned_faculty_ids],  # store as list of strings
        "created_at": datetime.datetime.now(datetime.timezone.utc)
    }

    db["courses"].insert_one(course_data)

    return RedirectResponse("/course", status_code=302)


@app.get("/course/{course_id}", response_class=HTMLResponse)
async def course_profile(request: Request, course_id: str):
    """
    Show course details of a single course, including assigned faculty.
    """
    user = request.session.get("user")
    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    course = db["courses"].find_one({
        "_id": ObjectId(course_id),
        "institute_id": str(institute["_id"])
    })
    if not course:
        return templates.TemplateResponse("course_profile.html", {
            "request": request,
            "error": "Course not found!"
        })

    # Convert ObjectId to string
    course["_id"] = str(course["_id"])

    # Fetch all faculties of this institute (for dropdown / display)
    faculties = list(db["faculties"].find({"institute_id": str(institute["_id"])}))
    for f in faculties:
        f["_id"] = str(f["_id"])

    return templates.TemplateResponse("course_profile.html", {
        "request": request,
        "course": course,
        "faculties": faculties
    })


@app.post("/course/update/{course_id}")
async def update_course(
        request: Request,
        course_id: str,
        name: str = Form(...),
        course_type: str = Form(...),
        assigned_faculty: list[str] = Form(...),  # Faculty ObjectId from form
        duration: str = Form(...),
        fees: float = Form(...),
        monthly_installments: float = Form(...),
        max_students: int = Form(...),
        start_date: str = Form(...),
        schedule_time: str = Form(...),
        subjects: str = Form(...),
        description: str = Form(...),
        status: str = Form("Active")
):
    """
    Update course details and optionally change assigned faculty.
    """
    user = request.session.get("user")
    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    # Convert subjects string → list
    subject_list = [s.strip() for s in subjects.split(",") if s.strip()]

    # Convert start_date string → datetime
    try:
        start_date_obj = datetime.datetime.strptime(start_date, "%Y-%m-%d")
    except ValueError:
        start_date_obj = start_date

        # assigned_faculty now is a list of strings from form
    if isinstance(assigned_faculty, str):
        # only one selected
        assigned_faculty_ids = [ObjectId(assigned_faculty)]
    else:
        # multiple selected
        assigned_faculty_ids = [ObjectId(fid) for fid in assigned_faculty]

        # You can store in your course document as a list
    course_update = {
        "institute_id": str(institute["_id"]),
        "name": name,
        "type": course_type,
        "duration": duration,
        "fee": fees,
        "monthly_installments": monthly_installments,
        "max_students": max_students,
        "start_date": start_date_obj,
        "schedule_time": schedule_time,
        "subjects": subject_list,
        "description": description,
        "status": status,
        "assigned_faculty": [str(fid) for fid in assigned_faculty_ids],  # store as list of strings
        "created_at": datetime.datetime.now(datetime.timezone.utc)
    }

    result = db["courses"].update_one(
        {"_id": ObjectId(course_id), "institute_id": str(institute["_id"])},
        {"$set": course_update}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Course not found")

    return RedirectResponse("/course", status_code=302)


@app.post("/course/delete/{course_id}")
async def delete_course(request: Request, course_id: str):
    """
    Permanently delete a faculty by ID.
    """
    user = request.session.get("user")
    if not user or user["role"] != "institute_admin":
        return RedirectResponse("/", status_code=302)

    # Get the current institute
    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    result = db["courses"].delete_one({"_id": ObjectId(course_id),
                                       "institute_id": str(institute["_id"])})

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Course not found")

    return RedirectResponse("/course", status_code=302)


# --------------------------
# ROUTE 15: Fees
# --------------------------


@app.get("/fees", response_class=HTMLResponse)
async def list_fees(
        request: Request,
        status: str = Query(None),  # Paid / Partial / Pay Later
        course_id: str = Query(None),  # Filter by course
        search: str = Query(None)  # Search by student name
):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        return templates.TemplateResponse("fees_profile.html", {
            "request": request,
            "students": [],
            "error": "No institute profile found!"
        })

    # Base query: only this institute's students
    students = list(db["students"].find({"institute_id": str(institute["_id"])}))

    # Enrich students with course, payments, and status
    for s in students:
        course = db["courses"].find_one({"_id": ObjectId(s["course_id"])})
        total_fee = course["fee"] if course else 0

        # If student already marked as Paid → full fee automatically
        if s.get("payment_status") == "Paid":
            paid_amount = total_fee
            pending_amount = 0
        else:
            payments = list(db["payments"].find({"student_id": str(s["_id"])}))
            paid_amount = sum([p.get("amount", 0) for p in payments])
            pending_amount = total_fee - paid_amount

            if paid_amount >= total_fee:
                s["payment_status"] = "Paid"
            elif paid_amount == 0:
                s["payment_status"] = s.get("payment_status", "Pay Later")
            elif paid_amount >= (0.5 * total_fee):  # 50% or more but not full
                s["payment_status"] = "Partial"
            else:
                s["payment_status"] = "Pending"  # Less than 50% treated as pending

        s["_id"] = str(s["_id"])
        s["course_name"] = course["name"] if course else "N/A"
        s["total_fee"] = total_fee
        s["paid_amount"] = paid_amount
        s["pending_amount"] = pending_amount

    # Apply filters
    if status:
        students = [s for s in students if s["payment_status"] == status]
    if course_id:
        students = [s for s in students if str(s["course_id"]) == course_id]
    if search:
        students = [s for s in students if search.lower() in s["name"].lower()]

    # For course filter dropdown
    courses = list(db["courses"].find({"institute_id": str(institute["_id"])}))

    return templates.TemplateResponse("fees.html", {
        "request": request,
        "students": students,
        "institute": institute,
        "selected_status": status or "",
        "selected_course": course_id or "",
        "search_query": search or "",
        "courses": courses
    })


# Show one student's fee details + history
@app.get("/fees/{student_id}", response_class=HTMLResponse)
async def fee_detail(request: Request, student_id: str):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    student = db["students"].find_one({"_id": ObjectId(student_id), "institute_id": str(institute["_id"])})
    if not student:
        return templates.TemplateResponse("fees_profile.html", {
            "request": request,
            "error": "Student not found!"
        })

    course = db["courses"].find_one({"_id": ObjectId(student["course_id"])})
    total_fee = course["fee"] if course else 0

    # Fetch payments
    payments = list(db["payments"].find({"student_id": str(student["_id"])}))
    paid_amount = sum([p["amount"] for p in payments])
    pending_amount = total_fee - paid_amount

    if paid_amount == total_fee:
        status = "Paid"
    elif paid_amount == 0:
        status = "Pay Later"
    elif paid_amount >= (0.5 * total_fee):
        status = "Partial"
    else:
        status = "Pending"

    student["_id"] = str(student["_id"])
    student["course_name"] = course["name"] if course else "N/A"
    student["total_fee"] = total_fee
    student["paid_amount"] = paid_amount
    student["pending_amount"] = pending_amount
    student["payment_status"] = status

    return templates.TemplateResponse("fees_details.html", {
        "request": request,
        "student": student,
        "payments": payments
    })


# Record a payment
@app.post("/fees/payment/collect/{student_id}")
async def collect_payment(
        request: Request,
        student_id: str,
        amount: float = Form(...),
        method: str = Form(...),
        date: str = Form(...),
        transaction_id: str = Form(None),
        receipt_number: str = Form(None),
        notes: str = Form(None)
):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    # Save this new payment in payments history
    payment_doc = {
        "institute_id": str(institute["_id"]),
        "student_id": student_id,
        "amount": amount,
        "method": method,
        "date": datetime.datetime.strptime(date, "%Y-%m-%d"),
        "transaction_id": transaction_id,
        "receipt_number": receipt_number,
        "notes": notes,
        "created_at": datetime.datetime.now(datetime.timezone.utc)
    }
    db["payments"].insert_one(payment_doc)

    # Recalculate paid & pending after new payment
    student = db["students"].find_one({"_id": ObjectId(student_id)})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")

    course = db["courses"].find_one({"_id": ObjectId(student["course_id"])})
    total_fee = course["fee"] if course else 0

    payments = list(db["payments"].find({"student_id": student_id}))
    paid_amount = sum([p["amount"] for p in payments])
    if paid_amount == total_fee:
        status = "Paid"
    elif paid_amount == 0:
        status = "Pay Later"
    elif paid_amount >= (0.5 * total_fee):
        status = "Partial"
    else:
        status = "Pending"

    # Update student payment_status
    db["students"].update_one(
        {"_id": ObjectId(student_id)},
        {"$set": {"payment_status": status}}
    )

    return RedirectResponse(f"/fees", status_code=302)


# -------------------
# Route 16 - Test
# ------------------------
@app.get("/tests", response_class=HTMLResponse)
async def list_tests(request: Request, course_id: str = None, q: str = None):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = db.institutes.find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    courses = list(db.courses.find({"institute_id": str(institute["_id"])}))
    course_map = {str(c["_id"]): c["name"] for c in courses}

    query = {"institute_id": str(institute["_id"])}
    if course_id:
        query["course_id"] = course_id

    tests = list(db.tests.find(query).sort("scheduled_date", -1))
    filtered_tests = []

    for t in tests:
        t["_id"] = str(t["_id"])
        t["course_name"] = course_map.get(t.get("course_id"), "Unknown Course")
        t["num_questions"] = int(t.get("num_questions", 0))
        t["total_marks"] = int(t.get("total_marks", 0))

        if t["status"] != "Scheduled":
            attendance = db.attendance.find_one({
                "course_id": t["course_id"],
                "date": t["scheduled_date"]
            })
            t["students_present"] = sum(1 for s in attendance["students"] if s.get("present")) if attendance else 0

            course = db.courses.find_one({"_id": ObjectId(t["course_id"])})
            t["max_students"] = course.get("max_students", 0) if course else 0

            students = t.get("students", [])
            t["marks_assigned"] = any(s.get("marks") is not None for s in students)

        # Apply search filter
        if q:
            if q.lower() in t["course_name"].lower() or q.lower() in t.get("subject", "").lower():
                filtered_tests.append(t)
        else:
            filtered_tests.append(t)

    return templates.TemplateResponse("tests.html", {
        "request": request,
        "tests": filtered_tests,
        "courses": courses,
        "selected_course": course_id,
        "search_query": q or ""
    })


# ------------------------
# New Test Form
# ------------------------
@app.get("/tests/new", response_class=HTMLResponse)
async def new_test(request: Request):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = db.institutes.find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    courses = list(db.courses.find({"institute_id": str(institute["_id"])}))

    return templates.TemplateResponse("test_form.html", {
        "request": request,
        "courses": courses
    })


# ------------------------
# Add Test
# ------------------------
@app.post("/tests/add")
async def add_test(request: Request):
    data = await request.form()
    user = request.session.get("user")
    institute = db.institutes.find_one({"user_email": user["email"]})

    test_doc = {
        "title": data.get("title"),
        "course_id": data.get("course_id"),
        "subject": data.get("subject"),  # manual entry
        "faculty_name": data.get("faculty"),  # manual entry
        "test_type": data.get("test_type"),
        "duration": data.get("duration"),
        "num_questions": int(data.get("num_questions")),
        "total_marks": int(data.get("total_marks")),
        "scheduled_date": data.get("scheduled_date"),
        "scheduled_time": data.get("scheduled_time"),
        "description": data.get("description"),
        "status": "Scheduled",
        "institute_id": str(institute["_id"]),
        "created_at": datetime.datetime.now(datetime.timezone.utc),
        "updated_at": datetime.datetime.now(datetime.timezone.utc)
    }

    db.tests.insert_one(test_doc)
    return RedirectResponse("/tests?success=1", status_code=302)


# ------------------------
# Edit Test Form
# ------------------------
@app.get("/tests/{test_id}", response_class=HTMLResponse)
async def edit_test(request: Request, test_id: str):
    test = db.tests.find_one({"_id": ObjectId(test_id)})
    if not test:
        return RedirectResponse("/tests", status_code=302)

    courses = list(db.courses.find({"institute_id": test["institute_id"]}))

    return templates.TemplateResponse("test_form.html", {
        "request": request,
        "test": test,
        "courses": courses
    })


# ------------------------
# Update Test
# ------------------------
@app.post("/tests/update/{test_id}")
async def update_test(test_id: str, request: Request):
    data = await request.form()

    db.tests.update_one(
        {"_id": ObjectId(test_id)},
        {"$set": {
            "title": data.get("title"),
            "course_id": data.get("course_id"),
            "subject": data.get("subject"),  # manual
            "faculty_name": data.get("faculty"),  # manual
            "test_type": data.get("test_type"),
            "duration": data.get("duration"),
            "num_questions": int(data.get("num_questions")),
            "total_marks": int(data.get("total_marks")),
            "scheduled_date": data.get("scheduled_date"),
            "scheduled_time": data.get("scheduled_time"),
            "description": data.get("description"),
            "updated_at": datetime.datetime.now(datetime.timezone.utc)
        }}
    )
    return RedirectResponse("/tests?updated=1", status_code=302)


# ------------------------
# Analytics Page
# ------------------------
@app.get("/tests/analytics/{test_id}", response_class=HTMLResponse)
async def test_analytics(request: Request, test_id: str):
    test = db.tests.find_one({"_id": ObjectId(test_id)})
    if not test:
        return RedirectResponse("/tests", status_code=302)

    attendance = db.attendance.find_one({
        "course_id": test["course_id"],
        "date": test["scheduled_date"]
    })

    students = []
    if attendance:
        ids = [s["student_id"] for s in attendance["students"] if s["present"]]
        students = list(db.students.find({"_id": {"$in": [ObjectId(x) for x in ids]}}))

    return templates.TemplateResponse("test_analytics.html", {
        "request": request,
        "test": test,
        "students": students
    })


# ------------------------
# Start Test
# ------------------------
@app.get("/tests/start/{test_id}")
async def start_test(test_id: str):
    test = db.tests.find_one({"_id": ObjectId(test_id)})
    if not test:
        return RedirectResponse("/tests", status_code=302)

    # fetch attendance for that course/date
    attendance = db.attendance.find_one({
        "course_id": test["course_id"],
        "date": test["scheduled_date"]
    })

    students_data = []
    if attendance:
        for s in attendance["students"]:
            if s.get("present"):
                students_data.append({
                    "student_id": s["student_id"],
                    "marks": 0  # initial marks 0, can be updated later
                })

    # Update the test document with students info and mark status as Ongoing
    db.tests.update_one(
        {"_id": ObjectId(test_id)},
        {"$set": {
            "students": students_data,
            "students_present": len(students_data),
            "max_students": len(students_data),  # or fetch from course if needed
            "status": "Ongoing",
            "updated_at": datetime.datetime.now(datetime.timezone.utc)
        }}
    )

    return RedirectResponse("/tests", status_code=302)


# ------------------------
# End Test
# ------------------------
@app.get("/tests/end/{test_id}")
async def end_test(test_id: str):
    db.tests.update_one(
        {"_id": ObjectId(test_id)},
        {"$set": {"status": "Completed", "updated_at": datetime.datetime.now(datetime.timezone.utc)}}
    )

    return RedirectResponse("/tests", status_code=302)


@app.post("/tests/analytics/save/{test_id}")
async def save_test_analytics(test_id: str, request: Request):
    test = db.tests.find_one({"_id": ObjectId(test_id)})
    if not test:
        return RedirectResponse("/tests", status_code=302)

    form_data = await request.form()
    marks_dict = {}
    for key, value in form_data.items():
        if key.startswith("marks[") and key.endswith("]"):
            student_id = key[6:-1]  # remove 'marks[' and ']'
            marks_dict[student_id] = int(value)

    updated_students = []
    for s in test.get("students", []):
        student_id = s["student_id"]
        if student_id in marks_dict:
            s["marks"] = marks_dict[student_id]
        else:
            s["marks"] = int(marks_dict.get(student_id, s.get("marks", 0)))
        updated_students.append(s)

    db.tests.update_one(
        {"_id": ObjectId(test_id)},
        {"$set": {"students": updated_students, "updated_at": datetime.datetime.now(datetime.timezone.utc)}}
    )

    return RedirectResponse("/tests", status_code=302)


@app.get("/tests/results/{test_id}", response_class=HTMLResponse)
async def view_test_results(request: Request, test_id: str):
    test = db.tests.find_one({"_id": ObjectId(test_id)})
    if not test:
        return RedirectResponse("/tests", status_code=302)

    # Fetch students with marks
    student_ids = [s["student_id"] for s in test.get("students", [])]
    students = list(db.students.find({"_id": {"$in": [ObjectId(x) for x in student_ids]}}))

    # Attach marks to each student
    marks_map = {s["student_id"]: s.get("marks", 0) for s in test.get("students", [])}
    for s in students:
        s["marks"] = marks_map.get(str(s["_id"]), 0)

    return templates.TemplateResponse("test_results.html", {
        "request": request,
        "test": test,
        "students": students
    })


# GET route to display the edit marks page
@app.get("/tests/edit-marks/{test_id}", response_class=HTMLResponse)
async def edit_marks(request: Request, test_id: str):
    test = db.tests.find_one({"_id": ObjectId(test_id)})
    if not test:
        return RedirectResponse("/tests", status_code=302)

    # Fetch students with their current marks
    students = []
    if "students" in test:
        for s in test["students"]:
            student_doc = db.students.find_one({"_id": ObjectId(s["student_id"])})
            if student_doc:
                students.append({
                    "_id": str(student_doc["_id"]),
                    "name": student_doc.get("name", "Unknown"),
                    "marks": s.get("marks", 0)
                })

    return templates.TemplateResponse("edit_marks.html", {
        "request": request,
        "test": test,
        "students": students
    })


# POST route to save updated marks
@app.post("/tests/edit-marks/{test_id}")
async def save_edited_marks(test_id: str, request: Request):
    data = await request.form()
    test = db.tests.find_one({"_id": ObjectId(test_id)})
    if not test:
        return RedirectResponse("/tests", status_code=302)

    # Update marks in the students array
    updated_students = []
    for s in test.get("students", []):
        student_id_str = str(s["student_id"])
        marks = int(data.get(f"marks_{student_id_str}", 0))
        updated_students.append({
            "student_id": s["student_id"],
            "marks": marks
        })

    db.tests.update_one(
        {"_id": ObjectId(test_id)},
        {"$set": {"students": updated_students, "marks_assigned": True}}
    )

    return RedirectResponse("/tests", status_code=302)


@app.post("/tests/delete/{test_id}")
async def delete_test(request: Request, test_id: str):
    # 1. Check user session
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    # 2. Get institute
    institute = db.institutes.find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    # 3. Delete test if it belongs to this institute
    result = db.tests.delete_one({
        "_id": ObjectId(test_id),
        "institute_id": str(institute["_id"])
    })

    if result.deleted_count:
        print(f"Test {test_id} deleted successfully")
    else:
        print(f"Test {test_id} not found or not authorized")

    # 4. Redirect back to tests page
    return RedirectResponse("/tests", status_code=302)


# -------------------
# Route 17 - Material
# ---------------------

@app.get("/materials", response_class=HTMLResponse)
async def list_materials(request: Request,
                         faculty_filter: str = None,
                         course: str = None,
                         type: str = None,
                         q: str = None):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = db["institutes"].find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    courses = list(db["courses"].find({"institute_id": str(institute["_id"])}))
    faculties = list(db["faculties"].find({"institute_id": str(institute["_id"])}))

    query = {"institute_id": str(institute["_id"])}

    if faculty_filter:
        query["uploaded_by"] = faculty_filter
    if course:
        query["course_id"] = course
    if type:
        query["material_type"] = type
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"tags": {"$regex": q, "$options": "i"}},
        ]

    materials = list(db["materials"].find(query))


    # enrich materials with course info
    for m in materials:
        if "course_id" in m:
            course_doc = db["courses"].find_one({"_id": ObjectId(m["course_id"])})
            if course_doc:
                m["course_name"] = course_doc["name"]
                m["course_type"] = course_doc.get("type")
                m["course_subjects"] = course_doc.get("subjects", [])
            # add file_size for each file stored in GridFS
        for f in m.get("files", []):
            try:
                grid_out = fs.get(ObjectId(f["file_id"]))
                f["file_size"] = grid_out.length  # in bytes
            except:
                f["file_size"] = 0  # fallback if file not found


    return templates.TemplateResponse("materials.html", {
        "request": request,
        "materials": materials,
        "courses": courses,
        "faculties": faculties,
        "faculty_filter": faculty_filter,
        "course_filter": course,
        "type_filter": type,
        "search_query": q
    })

MAX_FILE_SIZE = 5 * 1024 * 1024       # 5 MB per file
MAX_TOTAL_SIZE = 10 * 1024 * 1024

@app.post("/material/add")
async def add_material(request: Request,
                       title: str = Form(...),
                       subject: str = Form(...),
                       material_type: str = Form(...),
                       course: str = Form(...),
                       faculty_id: str = Form(...),
                       tags: str = Form(""),
                       description: str = Form(""),
                       files: list[UploadFile] = File(...)):

    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = db["institutes"].find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    faculty = db["faculties"].find_one({"_id": ObjectId(faculty_id)})
    if not faculty:
        return RedirectResponse("/materials", status_code=302)

    faculty_name = faculty["name"]

    course_doc = db["courses"].find_one({"_id": ObjectId(course),
                                        "institute_id": str(institute["_id"])})
    if not course_doc:
        return RedirectResponse("/materials", status_code=302)

    ALLOWED_EXTENSIONS = {".pdf", ".ppt", ".pptx", ".docx", ".jpeg", ".jpg", ".png"}
    saved_files = []
    total_size = 0

    for file in files:
        file_ext = os.path.splitext(file.filename)[1].lower()
        if file_ext not in ALLOWED_EXTENSIONS:
           continue


        content = await file.read()
        file_size = len(content)

        # check per file
        if file_size > MAX_FILE_SIZE:
            return templates.TemplateResponse("materials.html", {
                "request": request,
                "error": f"File {file.filename} exceeds 5 MB limit",
                "materials": list(db["materials"].find({"institute_id": str(institute["_id"])})),
                "courses": list(db["courses"].find({"institute_id": str(institute["_id"])}))
            })

        # check total size
        if total_size + file_size > MAX_TOTAL_SIZE:
            return templates.TemplateResponse("materials.html", {
                "request": request,
                "error": "Total upload size exceeds 10 MB limit",
                "materials": list(db["materials"].find({"institute_id": str(institute["_id"])})),
                "courses": list(db["courses"].find({"institute_id": str(institute["_id"])}))
            })

        # save to GridFS
        file_id = fs.put(content, filename=file.filename, content_type=file.content_type)
        saved_files.append({"file_name": file.filename, "file_id": str(file_id), "file_size": len(content) })
        total_size += file_size

    material_doc = {
        "title": title,
        "subject": subject,
        "material_type": material_type,
        "course_id": str(course_doc["_id"]),
        "course_name": course_doc["name"],
        "tags": [t.strip() for t in tags.split(",")] if tags else [],
        "description": description,
        "files": saved_files,
        "uploaded_by": faculty_name,
        "institute_id": str(institute["_id"]),
        "created_at": datetime.datetime.utcnow(),
        "downloads": 0
    }

    db["materials"].insert_one(material_doc)
    return RedirectResponse("/materials", status_code=303)

@app.get("/material/{material_id}", response_class=HTMLResponse)
async def view_material(request: Request, material_id: str):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = db["institutes"].find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    material = db["materials"].find_one({"_id": ObjectId(material_id),
                                        "institute_id": str(institute["_id"])})
    if not material:
        return RedirectResponse("/materials", status_code=302)

    courses = list(db["courses"].find({"institute_id": str(institute["_id"])}))
    faculties = list(db["faculties"].find({"institute_id": str(institute["_id"])}))

    if "course_id" in material:
        course_doc = db["courses"].find_one({"_id": ObjectId(material["course_id"])})
        if course_doc:
            material["course_name"] = course_doc["name"]
            material["course_type"] = course_doc.get("type")
            material["course_subjects"] = course_doc.get("subjects", [])
        # add file_size for GridFS files
    for f in material.get("files", []):
        try:
            grid_out = fs.get(ObjectId(f["file_id"]))
            f["file_size"] = grid_out.length  # in bytes
        except:
            f["file_size"] = 0  # fallback if file not found

    return templates.TemplateResponse("material_detail.html", {
        "request": request,
        "material": material,
        "faculties": faculties,
        "courses": courses
    })


@app.post("/material/update/{material_id}")
async def update_material(
        request: Request,
        material_id: str,
        title: str = Form(...),
        subject: str = Form(...),
        material_type: str = Form(...),
        course: str = Form(...),
        tags: str = Form(""),
        description: str = Form(...),
        files: list[UploadFile] = File(None)):

    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = db["institutes"].find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    existing_material = db["materials"].find_one({"_id": ObjectId(material_id),
                                                 "institute_id": str(institute["_id"])})
    course_doc = db["courses"].find_one({"_id": ObjectId(course),
                                        "institute_id": str(institute["_id"])})
    if not existing_material or not course_doc:
        return RedirectResponse(f"/material/{material_id}", status_code=302)

    # Handle removal of files
    form = await request.form()
    remove_files = form.getlist("remove_files")
    remaining_files = []
    total_size = 0

    if remove_files:
        for f in existing_material.get("files", []):
            if f["file_name"] in remove_files:
                fs.delete(ObjectId(f["file_id"]))
            else:
                remaining_files.append(f)
                # add size from GridFS
                try:
                    total_size += fs.get(ObjectId(f["file_id"])).length
                except:
                    pass
    else:
        remaining_files = existing_material.get("files", [])
        for f in remaining_files:
            try:
                total_size += fs.get(ObjectId(f["file_id"])).length
            except:
                pass

    # Handle new uploads
    ALLOWED_EXTENSIONS = {".pdf", ".ppt", ".pptx", ".docx", ".jpeg", ".jpg", ".png"}
    new_files = []
    if files and any(f.filename for f in files):
        for file in files:
            ext = os.path.splitext(file.filename)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                continue
            content = await file.read()
            file_size = len(content)

            # per file limit
            if file_size > MAX_FILE_SIZE:
                return templates.TemplateResponse("material_detail.html", {
                    "request": request,
                    "material": existing_material,
                    "error": f"File {file.filename} exceeds 5 MB limit",
                    "courses": list(db["courses"].find({"institute_id": str(institute["_id"])}))
                })

            # total limit
            if total_size + file_size > MAX_TOTAL_SIZE:
                return templates.TemplateResponse("material_detail.html", {
                    "request": request,
                    "material": existing_material,
                    "error": "Total upload size exceeds 10 MB limit",
                    "courses": list(db["courses"].find({"institute_id": str(institute["_id"])}))
                })

            file_id = fs.put(content, filename=file.filename, content_type=file.content_type)
            new_files.append({"file_name": file.filename, "file_id": str(file_id), "file_size": len(content) })
            total_size += file_size

    # combine files
    all_files = remaining_files + new_files

    # update MongoDB
    db["materials"].update_one(
        {"_id": ObjectId(material_id)},
        {"$set": {
            "title": title,
            "subject": subject,
            "material_type": material_type,
            "course_id": str(course_doc["_id"]),
            "course_name": course_doc["name"],
            "tags": [t.strip() for t in tags.split(",")] if tags else [],
            "description": description,
            "files": all_files,
            "updated_at": datetime.datetime.utcnow()
        }}
    )

    return RedirectResponse(f"/material/{material_id}", status_code=303)

@app.get("/material/download/{material_id}")
async def download_material(request: Request, material_id: str, file: str = None):
    """
    Download either a single file or all files as ZIP from GridFS
    """
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    material = db["materials"].find_one({
        "_id": ObjectId(material_id),
        "institute_id": str(institute["_id"])
    })
    if not material or "files" not in material or len(material["files"]) == 0:
        return RedirectResponse("/materials", status_code=302)

    # Increment download count
    db["materials"].update_one({"_id": ObjectId(material_id)}, {"$inc": {"downloads": 1}})

    # --- Single file download ---
    if file:
        target = next((f for f in material["files"] if f["file_name"] == file), None)
        if not target:
            return RedirectResponse(f"/material/{material_id}", status_code=302)

        grid_out = fs.get(ObjectId(target["file_id"]))
        file_bytes = io.BytesIO(grid_out.read())
        file_bytes.seek(0)

        return StreamingResponse(
            file_bytes,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={target['file_name']}"}
        )

    # --- Download all files as ZIP ---
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for f in material["files"]:
            try:
                grid_out = fs.get(ObjectId(f["file_id"]))
                zip_file.writestr(f["file_name"], grid_out.read())
            except Exception as e:
                # Skip missing or corrupted files
                continue

    zip_buffer.seek(0)
    return StreamingResponse(
        zip_buffer,
        media_type="application/x-zip-compressed",
        headers={"Content-Disposition": f"attachment; filename={material['title']}.zip"}
    )


@app.post("/material/delete/{material_id}")
async def delete_material(material_id: str):
    material = db["materials"].find_one({"_id": ObjectId(material_id)})
    if not material:
        return RedirectResponse("/materials", status_code=302)

    # delete files from GridFS
    for f in material.get("files", []):
        fs.delete(ObjectId(f["file_id"]))

    db["materials"].delete_one({"_id": ObjectId(material_id)})
    return RedirectResponse("/materials", status_code=303)


# -------------------
# Route 18 - Attendance
# ---------------------

@app.get("/attendance", response_class=HTMLResponse)
async def attendance_page(request: Request, course_id: str = None, date: str = None):
    """
    Show attendance page with courses filter and optional date filter
    """
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    # Get the institute document
    institute = db.institutes.find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    # Now fetch courses of this institute
    courses = list(db.courses.find({"institute_id": str(institute["_id"])}))

    # fetch students for selected course if course_id given
    students = []
    if course_id:
        students = list(db.students.find({
            "course_id": str(course_id),
            "status": "Active"
        }))

    return templates.TemplateResponse("attendance.html", {
        "request": request,
        "courses": courses,
        "students": students,
        "selected_course": course_id,
        "selected_date": date
    })


@app.post("/attendance/add")
async def add_attendance(request: Request):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    data = await request.form()
    course_id = str(data.get("course_id"))
    date = data.get("date")

    students_data = []
    for key in data.keys():
        if key.startswith("status_"):
            student_id = key.replace("status_", "")
            present = True if data.get(key) == "present" else False
            students_data.append({
                "student_id": student_id,
                "present": present
            })

    db.attendance.insert_one({
        "course_id": course_id,  # always string
        "date": date,
        "students": students_data,
        "created_at": datetime.datetime.now(datetime.timezone.utc)
    })

    return RedirectResponse(f"/attendance?course_id={course_id}&date={date}&success=1", status_code=302)


@app.post("/attendance/update/{attendance_id}")
async def update_attendance(attendance_id: str, request: Request):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    data = await request.form()
    students_data = []
    for key in data.keys():
        if key.startswith("status_"):
            student_id = key.replace("status_", "")
            present = True if data.get(key) == "present" else False
            students_data.append({
                "student_id": student_id,
                "present": present
            })

    db.attendance.update_one(
        {"_id": ObjectId(attendance_id)},
        {"$set": {"students": students_data, "updated_at": datetime.datetime.now(datetime.timezone.utc)}}
    )

    return RedirectResponse(f"/attendance/{attendance_id}?success=1", status_code=302)


@app.get("/attendance/history", response_class=HTMLResponse)
async def attendance_history(request: Request, course_id: str = None, date: str = None):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = db.institutes.find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    courses = list(db.courses.find({"institute_id": str(institute["_id"])}))

    attendance_records = []
    if course_id and date:  # ✅ only when both selected
        query = {
            "course_id": str(course_id),
            "date": date
        }
        records = list(db.attendance.find(query).sort("date", -1))

        # expand student data
        for r in records:
            for s in r.get("students", []):
                student = db.students.find_one({"_id": ObjectId(s["student_id"])})
                if student:
                    attendance_records.append({
                        "_id": r["_id"],
                        "date": r["date"],
                        "student_name": student["name"],
                        "phone": student["phone"],
                        "status": "Present" if s["present"] else "Absent"
                    })

    return templates.TemplateResponse("attendance_history.html", {
        "request": request,
        "attendance_records": attendance_records,  # ✅ now sends built list
        "courses": courses,
        "selected_course": course_id,
        "selected_date": date
    })


@app.get("/attendance/{attendance_id}", response_class=HTMLResponse)
async def get_attendance(request: Request, attendance_id: str):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        return RedirectResponse("/", status_code=302)

    attendance = db.attendance.find_one({"_id": ObjectId(attendance_id)})
    if not attendance:
        return RedirectResponse("/attendance", status_code=302)

    # fetch students for the course (make sure course_id is str)
    students = list(db.students.find({
        "course_id": str(attendance["course_id"]),
        "status": "Active"
    }))

    return templates.TemplateResponse("attendance_edit.html", {
        "request": request,
        "attendance": attendance,
        "students": students
    })


# -------------------
# Route 19 - Reports
# ---------------------
@app.get("/reports", response_class=HTMLResponse)
async def institute_reports(request: Request, download: int = 0):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    institute_id = str(institute["_id"])
    today = datetime.datetime.today()

    # --- Revenue: Current vs Previous Month ---
    start_current_month = datetime.datetime(today.year, today.month, 1)
    start_prev_month = (start_current_month - datetime.timedelta(days=1)).replace(day=1)

    def get_revenue(start_date, end_date=None):
        match_stage = {
            "institute_id": institute_id,
            "date": {"$gte": start_date}
        }
        if end_date:
            match_stage["date"]["$lt"] = end_date

        cursor = db["payments"].aggregate([
            {"$match": match_stage},
            {"$group": {"_id": None, "total": {"$sum": {"$toDouble": "$amount"}}}}
        ])
        return next(cursor, {}).get("total", 0)

    current_revenue = get_revenue(start_current_month)
    prev_revenue = get_revenue(start_prev_month, start_current_month)

    revenue_growth_percent = (
        round(((current_revenue - prev_revenue) / prev_revenue) * 100)
        if prev_revenue > 0 else
        (100 if current_revenue > 0 else 0)
    )

    # --- Total Tests Completed ---
    total_test = db["tests"].count_documents({
        "institute_id": institute_id, "status": "Completed"
    })

    # --- Active Faculties ---
    active_faculty = db["faculties"].count_documents({"institute_id": institute_id})

    # --- Total Students ---
    total_students = db["students"].count_documents({
        "institute_id": institute_id, "status": "Active"
    })

    # --- Students Added This Month vs Last Month ---
    first_day_this_month = start_current_month
    first_day_last_month = start_prev_month

    this_month_count = db["students"].count_documents({
        "institute_id": institute_id,
        "status": "Active",
        "joined_date": {"$gte": first_day_this_month.strftime("%Y-%m-%d")}
    })
    last_month_count = db["students"].count_documents({
        "institute_id": institute_id,
        "status": "Active",
        "joined_date": {"$gte": first_day_last_month.strftime("%Y-%m-%d"),
                        "$lt": first_day_this_month.strftime("%Y-%m-%d")}
    })

    student_growth_percent = (
        round(((this_month_count - last_month_count) / last_month_count) * 100)
        if last_month_count > 0 else
        (100 if this_month_count > 0 else 0)
    )

    # --- Monthly Summary (Last 4 Months) ---
    monthly_summary = []

    for i in range(3, -1, -1):
        month = today.month - i
        year = today.year
        while month <= 0:
            month += 12
            year -= 1

        month_start = datetime.datetime(year, month, 1)

        if i == 0:
            month_end = datetime.datetime.max
        else:
            if month == 12:
                next_month_start = datetime.datetime(year + 1, 1, 1)
            else:
                next_month_start = datetime.datetime(year, month + 1, 1)
            month_end = next_month_start - datetime.timedelta(seconds=1)

        students_count = db["students"].count_documents({
            "institute_id": institute_id,
            "status": "Active",
            "joined_date": {"$gte": month_start.strftime("%Y-%m-%d"),
                            "$lte": month_end.strftime("%Y-%m-%d")}
        })

        tests_count = db["tests"].count_documents({
            "institute_id": institute_id,
            "status": "Completed",
            "scheduled_date": {"$gte": month_start.strftime("%Y-%m-%d"),
                               "$lte": month_end.strftime("%Y-%m-%d")}
        })

        revenue_cursor = db["payments"].aggregate([
            {"$match": {
                "institute_id": institute_id,
                "date": {"$gte": month_start, "$lte": month_end}
            }},
            {"$group": {"_id": None, "total": {"$sum": {"$toDouble": "$amount"}}}}
        ])
        revenue = next(revenue_cursor, {}).get("total", 0)

        monthly_summary.append({
            "month": month_start.strftime("%b %Y"),
            "students": students_count,
            "tests": tests_count,
            "revenue": revenue
        })

    # --- Payments Summary ---
    statuses = ["Paid", "Partial", "Pay Later", "Pending"]
    payment_summary = {}
    for status in statuses:
        students_cursor = db["students"].find({
            "institute_id": institute_id, "payment_status": status
        }, {"_id": 1})
        student_ids = [str(s["_id"]) for s in students_cursor]

        total_paid = 0
        if student_ids:
            total_paid_cursor = db["payments"].aggregate([
                {"$match": {"student_id": {"$in": student_ids}, "institute_id": institute_id}},
                {"$group": {"_id": None, "total": {"$sum": {"$toDouble": "$amount"}}}}
            ])
            total_paid = next(total_paid_cursor, {}).get("total", 0)

        payment_summary[status] = {
            "students": len(student_ids),
            "paid_amount": total_paid
        }

    # --- Top Performers ---
    current_month_start = datetime.datetime(today.year, today.month, 1)
    tests_cursor = db["tests"].find({
        "institute_id": institute_id, "status": "Completed"
    }).sort("scheduled_date", -1)

    top_performers = []
    for test in tests_cursor:
        try:
            test_date = datetime.datetime.strptime(test["scheduled_date"], "%Y-%m-%d")
        except:
            continue
        if test_date < current_month_start:
            continue

        course_name = "Unknown Course"
        course = db["courses"].find_one({"_id": ObjectId(test.get("course_id", ""))})
        if course:
            course_name = course.get("name", "Unknown Course")

        total_marks = int(test.get("total_marks", 0))
        test_title = test.get("title", "Unknown Test")

        for student_entry in sorted(test.get("students", []), key=lambda x: x.get("marks", 0), reverse=True)[:2]:
            marks_obtained = int(student_entry.get("marks", 0))
            student = db["students"].find_one({"_id": ObjectId(student_entry["student_id"])})
            student_name = student.get("name", "Unknown Student") if student else "Unknown Student"

            percentage = (marks_obtained / total_marks * 100) if total_marks > 0 else 0
            top_performers.append({
                "student_name": student_name,
                "course_name": course_name,
                "test_title": test_title,
                "marks_obtained": marks_obtained,
                "total_marks": total_marks,
                "percentage": round(percentage, 2),
                "scheduled_date": test_date
            })

    top_performers = sorted(top_performers, key=lambda x: x["percentage"], reverse=True)[:10]

    # --- Prepare context ---
    context = {
        "request": request,
        "institute": institute,
        "total_students": total_students,
        "student_growth_percent": student_growth_percent,
        "monthly_revenue": current_revenue,
        "revenue_growth_percent": revenue_growth_percent,
        "total_test": total_test,
        "active_faculty": active_faculty,
        "monthly_summary": monthly_summary,
        "payment_summary": payment_summary,
        "top_performers": top_performers
    }

    # --- Check if download requested ---
    if download:
        rendered_html = templates.get_template("reports.html").render(**context)
        return Response(
            rendered_html,
            media_type="text/html",
            headers={"Content-Disposition": 'attachment; filename="institute_analytics.html"'}
        )

    # --- Normal render ---
    return templates.TemplateResponse("reports.html", context)


@app.get("/course-performance", response_class=HTMLResponse)
async def course_performance(request: Request):
    user = request.session.get("user")
    if not user or user.get("role") != "institute_admin":
        return RedirectResponse("/", status_code=302)

    institute = institutes_collection.find_one({"user_email": user["email"]})
    if not institute:
        raise HTTPException(status_code=400, detail="Institute not found")

    institute_id = str(institute["_id"])

    # Filters
    course_id_filter = request.query_params.get("course_id")
    subject_filter = request.query_params.get("subject")
    month_filter = request.query_params.get("month")
    month_filter = int(month_filter) if month_filter else None

    filter_top_performers = []

    # Fetch all completed tests for this institute
    tests_cursor = db["tests"].find({
        "institute_id": institute_id,
        "status": "Completed",
    }).sort("scheduled_date", -1)

    for test in tests_cursor:
        try:
            test_date = datetime.datetime.strptime(test["scheduled_date"], "%Y-%m-%d")
        except:
            continue

        # Apply course filter
        if course_id_filter and test["course_id"] != course_id_filter:
            continue
        # Apply subject filter
        if subject_filter and test.get("subject") != subject_filter:
            continue

        # Apply month filter
        if month_filter and test_date.month != month_filter:
            continue

        # Fetch course name
        course_name = "Unknown Course"
        try:
            course = db["courses"].find_one({"_id": ObjectId(test["course_id"])})
            if course:
                course_name = course.get("name", "Unknown Course")
        except Exception as e:
            print("Error fetching course:", e)

        total_marks = int(test.get("total_marks", 0))
        test_title = test.get("title", "Unknown Test")

        # Top 3 students
        students_sorted = sorted(
            test.get("students", []),
            key=lambda x: x.get("marks", 0),
            reverse=True
        )[:3]

        for student_entry in students_sorted:
            marks_obtained = int(student_entry.get("marks", 0))
            student_name = "Unknown Student"

            try:
                student = db["students"].find_one({"_id": ObjectId(student_entry["student_id"])})
                if student:
                    student_name = student.get("name", "Unknown Student")
            except:
                pass

            percentage = (marks_obtained / total_marks * 100) if total_marks > 0 else 0

            filter_top_performers.append({
                "student_name": student_name,
                "course_name": course_name,
                "test_title": test_title,
                "marks_obtained": marks_obtained,
                "total_marks": total_marks,
                "percentage": round(percentage, 2),
                "scheduled_date": test_date
            })

    # Fetch all courses for dropdown
    courses = list(db["courses"].find({"institute_id": institute_id, "status": "Active"}))
    # Collect all subjects
    subjects = []
    for course in courses:
        if "subjects" in course:
            subjects.extend(course["subjects"])

    # Remove duplicates
    subjects = list(set(subjects))
    return templates.TemplateResponse("course_performance.html", {
        "request": request,
        "subjects": subjects,
        "filter_top_performers": filter_top_performers,
        "courses": courses,
        "subject_filter": subject_filter,
        "month_filter": month_filter,
        "course_id_filter": course_id_filter
    })

# --------------------------
# ROUTE 7: Admin Dashboard
# --------------------------
@app.get("/admin-dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    user = request.session.get("user")
    if not user or user["role"] != "platform_admin":
        return RedirectResponse("/", status_code=302)

    # Example analytics (later replace with real data)
    total_institutes = institutes_collection.count_documents({})
    total_users = users_collection.count_documents({"role": "institute_admin"})

    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "user": user,
        "total_institutes": total_institutes,
        "total_users": total_users
    })
@app.get("/client-institutes",response_class=HTMLResponse)
async def institutes_list(request:Request):

    return templates.TemplateResponse("list_institutes.html",
                                    {"request":request})

@app.get("/subscriptions",response_class=HTMLResponse)
async def list_subscription(request:Request):

    return templates.TemplateResponse("subscription.html",
                                    {"request":request})

@app.get("/system-reports",response_class=HTMLResponse)
async def list_subscription(request:Request):

    return templates.TemplateResponse("admin_reports.html",
                                      {"request":request})