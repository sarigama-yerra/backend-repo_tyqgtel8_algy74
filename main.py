import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import (
    User, Session as SessionModel, Vitals, Patient, Allergy, HistoryEntry,
    HistoryAudit, Medication, MedReminderEvent, EmergencyContact, Surgery, Settings
)

APP_INACTIVITY_MINUTES = int(os.getenv("SESSION_INACTIVITY_MINUTES", "20"))
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "240"))

app = FastAPI(title="PulsePoint API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----- Utilities -----

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def make_token() -> str:
    return secrets.token_urlsafe(32)


class LoginPasswordRequest(BaseModel):
    id_number: str
    password: str


class LoginQRRequest(BaseModel):
    qr_code: str


class LoginBiometricRequest(BaseModel):
    id_number: str
    biometric_token: str


class TokenResponse(BaseModel):
    token: str
    role: str
    expires_at: datetime
    inactivity_minutes: int


class OTCMedicationRequest(BaseModel):
    name: str
    dosage: str
    frequency: str
    start_date: str
    end_date: Optional[str] = None


# ----- Auth helpers -----

def get_session_from_token(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    sess = db["session"].find_one({"token": token, "active": True})
    if not sess:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    now = datetime.now(timezone.utc)
    last = sess.get("last_activity")
    expires_at = sess.get("expires_at")

    if expires_at and now > expires_at:
        db["session"].update_one({"_id": sess["_id"]}, {"$set": {"active": False}})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")

    if last and (now - last) > timedelta(minutes=APP_INACTIVITY_MINUTES):
        db["session"].update_one({"_id": sess["_id"]}, {"$set": {"active": False}})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Auto-logout due to inactivity")

    # Update last activity
    db["session"].update_one({"_id": sess["_id"]}, {"$set": {"last_activity": now}})
    return sess


def require_role(sess: Dict[str, Any], roles: List[str]):
    if sess.get("role") not in roles:
        raise HTTPException(status_code=403, detail="Insufficient permissions")


# ----- Public endpoints -----

@app.get("/")
def root():
    return {"name": "PulsePoint API", "status": "ok"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "❌ Not Set",
        "database_name": "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected & Working"
            response["database_url"] = "✅ Set"
            response["database_name"] = getattr(db, "name", "✅ Set")
            response["connection_status"] = "Connected"
            try:
                response["collections"] = db.list_collection_names()[:10]
            except Exception:
                pass
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# ----- Bootstrap helper (create user if not exists) -----
class BootstrapUserRequest(BaseModel):
    id_number: str
    full_name: str
    password: str
    role: str = "patient"
    email: Optional[str] = None


@app.post("/auth/bootstrap")
def bootstrap_user(payload: BootstrapUserRequest):
    existing = db["user"].find_one({"id_number": payload.id_number})
    if existing:
        return {"message": "User already exists"}
    user: dict = User(
        id_number=payload.id_number,
        full_name=payload.full_name,
        role=payload.role if payload.role in ("patient", "doctor") else "patient",
        email=payload.email,
        password_hash=hash_password(payload.password)
    ).model_dump()
    create_document("user", user)
    # Also create default settings
    settings = Settings(id_number=payload.id_number).model_dump()
    create_document("settings", settings)
    return {"message": "User created"}


# ----- Authentication -----
@app.post("/auth/login/password", response_model=TokenResponse)
def login_password(payload: LoginPasswordRequest):
    user = db["user"].find_one({"id_number": payload.id_number})
    if not user or user.get("password_hash") != hash_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = make_token()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=SESSION_TTL_MINUTES)
    session = SessionModel(
        token=token,
        id_number=user["id_number"],
        role=user["role"],
        created_at=now,
        last_activity=now,
        expires_at=expires,
        active=True
    ).model_dump()
    create_document("session", session)
    return TokenResponse(token=token, role=user["role"], expires_at=expires, inactivity_minutes=APP_INACTIVITY_MINUTES)


@app.post("/auth/login/qr", response_model=TokenResponse)
def login_qr(payload: LoginQRRequest):
    # For MVP, treat qr_code as id_number token issued by the clinic kiosk
    user = db["user"].find_one({"id_number": payload.qr_code})
    if not user:
        raise HTTPException(status_code=404, detail="QR not recognized")
    token = make_token()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=SESSION_TTL_MINUTES)
    session = SessionModel(
        token=token,
        id_number=user["id_number"],
        role=user["role"],
        created_at=now,
        last_activity=now,
        expires_at=expires,
        active=True
    ).model_dump()
    create_document("session", session)
    return TokenResponse(token=token, role=user["role"], expires_at=expires, inactivity_minutes=APP_INACTIVITY_MINUTES)


@app.post("/auth/login/biometric", response_model=TokenResponse)
def login_biometric(payload: LoginBiometricRequest):
    # Biometric validation would normally be on-device; we accept a valid user id for MVP
    user = db["user"].find_one({"id_number": payload.id_number})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    token = make_token()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=SESSION_TTL_MINUTES)
    session = SessionModel(
        token=token,
        id_number=user["id_number"],
        role=user["role"],
        created_at=now,
        last_activity=now,
        expires_at=expires,
        active=True
    ).model_dump()
    create_document("session", session)
    return TokenResponse(token=token, role=user["role"], expires_at=expires, inactivity_minutes=APP_INACTIVITY_MINUTES)


@app.post("/auth/logout")
def logout(sess=Depends(get_session_from_token)):
    db["session"].update_one({"_id": sess["_id"]}, {"$set": {"active": False}})
    return {"message": "Logged out"}


@app.get("/me")
def me(sess=Depends(get_session_from_token)):
    user = db["user"].find_one({"id_number": sess["id_number"]}, {"password_hash": 0})
    return {"user": user}


# ----- Vitals & Patient -----
class VitalsUpdateRequest(BaseModel):
    height_cm: Optional[float] = None
    weight_kg: Optional[float] = None
    height_in: Optional[float] = None
    weight_lbs: Optional[float] = None
    blood_group: Optional[str] = None
    rh_factor: Optional[str] = None


@app.get("/patient/vitals")
def get_vitals(sess=Depends(get_session_from_token)):
    doc = db["patient"].find_one({"id_number": sess["id_number"]})
    return doc.get("vitals") if doc else None


@app.put("/patient/vitals")
def update_vitals(payload: VitalsUpdateRequest, sess=Depends(get_session_from_token)):
    require_role(sess, ["doctor"])  # only doctors can edit vitals
    patient = db["patient"].find_one({"id_number": sess["id_number"]})
    target_id = sess["id_number"] if not patient else patient["id_number"]
    # For simplicity, edit vitals for the session owner's id_number. In real app, doctor selects patient.
    vitals = db["patient"].find_one({"id_number": target_id}) or {"id_number": target_id, "full_name": ""}
    new_vitals = {k: v for k, v in payload.model_dump().items() if v is not None}
    # BMI auto-calc if height/weight provided
    if new_vitals.get("height_cm") and new_vitals.get("weight_kg"):
        h_m = new_vitals["height_cm"] / 100
        new_vitals["bmi"] = round(new_vitals["weight_kg"] / (h_m * h_m), 2)
    db["patient"].update_one(
        {"id_number": target_id},
        {"$set": {"vitals": new_vitals}},
        upsert=True
    )
    return {"status": "ok"}


# ----- Allergies -----
class AllergyCreate(BaseModel):
    id_number: Optional[str] = None
    substance: str
    severity: str
    emergency: bool = False
    notes: Optional[str] = None
    physician: str


@app.get("/patient/allergies")
def list_allergies(id_number: Optional[str] = None, sess=Depends(get_session_from_token)):
    target = id_number or sess["id_number"]
    return get_documents("allergy", {"id_number": target})


@app.post("/patient/allergies")
def add_allergy(payload: AllergyCreate, sess=Depends(get_session_from_token)):
    require_role(sess, ["doctor"])  # doctor editable
    target = payload.id_number or sess["id_number"]
    doc = Allergy(
        id_number=target,
        substance=payload.substance,
        severity=payload.severity,  # validated by schema
        emergency=payload.emergency,
        notes=payload.notes,
        physician=payload.physician,
        timestamp=datetime.now(timezone.utc)
    ).model_dump()
    create_document("allergy", doc)
    return {"status": "created"}


# ----- Medical History -----
class HistoryCreate(BaseModel):
    id_number: Optional[str] = None
    physician: str
    physician_credentials: Optional[str] = None
    facility_name: str
    facility_address: Optional[str] = None
    treatment_summary: str


@app.get("/patient/history")
def list_history(
    id_number: Optional[str] = None,
    doctor: Optional[str] = Query(None),
    hospital: Optional[str] = Query(None),
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    sess=Depends(get_session_from_token)
):
    target = id_number or sess["id_number"]
    filt: Dict[str, Any] = {"id_number": target}
    if doctor:
        filt["physician"] = doctor
    if hospital:
        filt["facility_name"] = hospital
    items = get_documents("historyentry", filt)
    # date filter by ISO string compare if provided
    def in_range(ts: datetime) -> bool:
        if not isinstance(ts, datetime):
            return True
        ok = True
        if start:
            ok = ok and ts >= datetime.fromisoformat(start)
        if end:
            ok = ok and ts <= datetime.fromisoformat(end)
        return ok
    items = [i for i in items if in_range(i.get("timestamp", datetime.now(timezone.utc)))]
    items.sort(key=lambda x: x.get("timestamp", datetime.now(timezone.utc)))
    return items


@app.post("/patient/history")
def add_history(payload: HistoryCreate, sess=Depends(get_session_from_token)):
    require_role(sess, ["doctor"])  # doctor editable
    target = payload.id_number or sess["id_number"]
    doc = HistoryEntry(
        id_number=target,
        physician=payload.physician,
        physician_credentials=payload.physician_credentials,
        facility_name=payload.facility_name,
        facility_address=payload.facility_address,
        timestamp=datetime.now(timezone.utc),
        treatment_summary=payload.treatment_summary
    ).model_dump()
    create_document("historyentry", doc)
    return {"status": "created"}


# ----- Medications -----
class MedicationCreate(BaseModel):
    id_number: Optional[str] = None
    name: str
    dosage: str
    frequency: str
    prescribing_physician: Optional[str] = None
    start_date: str
    end_date: Optional[str] = None
    pediatric: bool = False


@app.get("/patient/medications")
def list_medications(id_number: Optional[str] = None, sess=Depends(get_session_from_token)):
    target = id_number or sess["id_number"]
    meds = get_documents("medication", {"id_number": target})
    return meds


@app.post("/patient/medications")
def add_medication(payload: MedicationCreate, sess=Depends(get_session_from_token)):
    target = payload.id_number or sess["id_number"]
    if sess["role"] == "doctor":
        doc = Medication(
            id_number=target,
            name=payload.name,
            dosage=payload.dosage,
            frequency=payload.frequency,
            prescribing_physician=payload.prescribing_physician or "",
            start_date=payload.start_date,
            end_date=payload.end_date,
            pediatric=payload.pediatric,
            source="doctor",
            approved=True
        ).model_dump()
    else:
        # patient self-add OTC; requires approval
        doc = Medication(
            id_number=target,
            name=payload.name,
            dosage=payload.dosage,
            frequency=payload.frequency,
            prescribing_physician=payload.prescribing_physician or "",
            start_date=payload.start_date,
            end_date=payload.end_date,
            pediatric=payload.pediatric,
            source="patient_otc",
            approved=False
        ).model_dump()
    create_document("medication", doc)
    return {"status": "created"}


class ApproveMedicationRequest(BaseModel):
    approved: bool


@app.post("/patient/medications/{med_id}/approve")
def approve_medication(med_id: str, payload: ApproveMedicationRequest, sess=Depends(get_session_from_token)):
    require_role(sess, ["doctor"])  # only doctors
    res = db["medication"].update_one({"_id": db["medication"]._Database__client.get_default_database().client.codec_options.document_class().get("_id", med_id)}, {"$set": {"approved": payload.approved}})
    # fallback simple update by string _id
    try:
        from bson import ObjectId
        db["medication"].update_one({"_id": ObjectId(med_id)}, {"$set": {"approved": payload.approved}})
    except Exception:
        pass
    return {"status": "ok"}


@app.post("/medications/{med_id}/events")
def medication_event(med_id: str, notes: Optional[str] = None, event_type: str = "reminder", sess=Depends(get_session_from_token)):
    evt = MedReminderEvent(
        medication_id=med_id,
        id_number=sess["id_number"],
        event_type=event_type,  # reminder/confirm/snooze/symptom_check
        notes=notes,
        timestamp=datetime.now(timezone.utc)
    ).model_dump()
    create_document("medreminderevent", evt)
    return {"status": "logged"}


# ----- Emergency Contacts -----
class ContactCreate(BaseModel):
    name: str
    relationship: str
    phones: List[str]
    primary: bool = False


@app.get("/patient/contacts")
def list_contacts(sess=Depends(get_session_from_token)):
    return get_documents("emergencycontact", {"id_number": sess["id_number"]})


@app.post("/patient/contacts")
def add_contact(payload: ContactCreate, sess=Depends(get_session_from_token)):
    doc = EmergencyContact(
        id_number=sess["id_number"],
        name=payload.name,
        relationship=payload.relationship,
        phones=payload.phones,
        primary=payload.primary
    ).model_dump()
    create_document("emergencycontact", doc)
    return {"status": "created"}


# ----- Surgeries -----
class SurgeryCreate(BaseModel):
    id_number: Optional[str] = None
    procedure: str
    date: str
    surgeon: str
    hospital: str
    notes: Optional[str] = None


@app.get("/patient/surgeries")
def list_surgeries(id_number: Optional[str] = None, sess=Depends(get_session_from_token)):
    target = id_number or sess["id_number"]
    return get_documents("surgery", {"id_number": target})


@app.post("/patient/surgeries")
def add_surgery(payload: SurgeryCreate, sess=Depends(get_session_from_token)):
    require_role(sess, ["doctor"])  # read-only for patients, doctor editable
    target = payload.id_number or sess["id_number"]
    doc = Surgery(
        id_number=target,
        procedure=payload.procedure,
        date=payload.date,
        surgeon=payload.surgeon,
        hospital=payload.hospital,
        notes=payload.notes
    ).model_dump()
    create_document("surgery", doc)
    return {"status": "created"}


# ----- Settings -----
class SettingsUpdate(BaseModel):
    theme: Optional[str] = None
    font_size: Optional[str] = None
    notify_medications: Optional[bool] = None
    notify_appointments: Optional[bool] = None
    data_sharing: Optional[bool] = None


@app.get("/patient/settings")
def get_settings(sess=Depends(get_session_from_token)):
    doc = db["settings"].find_one({"id_number": sess["id_number"]}, {"_id": 0})
    if not doc:
        defaults = Settings(id_number=sess["id_number"]).model_dump()
        create_document("settings", defaults)
        return defaults
    return doc


@app.put("/patient/settings")
def update_settings(payload: SettingsUpdate, sess=Depends(get_session_from_token)):
    new_vals = {k: v for k, v in payload.model_dump().items() if v is not None}
    db["settings"].update_one({"id_number": sess["id_number"]}, {"$set": new_vals}, upsert=True)
    return {"status": "ok"}
