"""
PulsePoint Database Schemas

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).
These schemas are used to validate incoming/outgoing data at the API layer.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

# Roles
class User(BaseModel):
    id_number: str = Field(..., description="Government/Medical ID number")
    full_name: str
    email: Optional[EmailStr] = None
    role: Literal["patient", "doctor"] = "patient"
    password_hash: Optional[str] = Field(None, description="Hashed password")

class Session(BaseModel):
    token: str
    id_number: str
    role: Literal["patient", "doctor"]
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    active: bool = True

# Patient core profile and vitals
class Vitals(BaseModel):
    height_cm: Optional[float] = None
    weight_kg: Optional[float] = None
    height_in: Optional[float] = None
    weight_lbs: Optional[float] = None
    bmi: Optional[float] = None
    blood_group: Optional[str] = Field(None, description="e.g., A, B, AB, O")
    rh_factor: Optional[Literal["+", "-"]] = None

class Patient(BaseModel):
    id_number: str
    full_name: str
    date_of_birth: Optional[str] = None
    vitals: Optional[Vitals] = None

# Allergies
class Allergy(BaseModel):
    id_number: str
    substance: str
    severity: Literal["mild", "moderate", "severe"]
    emergency: bool = False
    notes: Optional[str] = None
    physician: str = Field(..., description="Physician name and credentials")
    timestamp: datetime

# Medical history
class HistoryEntry(BaseModel):
    id_number: str
    physician: str
    physician_credentials: Optional[str] = None
    facility_name: str
    facility_address: Optional[str] = None
    timestamp: datetime
    treatment_summary: str

class HistoryAudit(BaseModel):
    entry_id: str
    changed_by: str
    change_note: str
    timestamp: datetime

# Medications
class Medication(BaseModel):
    id_number: str
    name: str
    dosage: str
    frequency: str
    prescribing_physician: str
    start_date: str
    end_date: Optional[str] = None
    pediatric: bool = False
    source: Literal["doctor", "patient_otc"] = "doctor"
    approved: bool = True

class MedReminderEvent(BaseModel):
    medication_id: str
    id_number: str
    event_type: Literal["reminder", "confirm", "snooze", "symptom_check"]
    notes: Optional[str] = None
    timestamp: datetime

# Contacts
class EmergencyContact(BaseModel):
    id_number: str
    name: str
    relationship: str
    phones: List[str]
    primary: bool = False

# Surgeries
class Surgery(BaseModel):
    id_number: str
    procedure: str
    date: str
    surgeon: str
    hospital: str
    notes: Optional[str] = None

# Settings
class Settings(BaseModel):
    id_number: str
    theme: Literal["light", "dark", "system"] = "system"
    font_size: Literal["sm", "md", "lg", "xl"] = "md"
    notify_medications: bool = True
    notify_appointments: bool = True
    data_sharing: bool = False

