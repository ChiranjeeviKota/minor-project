from sqlalchemy import Column, Integer, String, Float, ForeignKey, Date
from sqlalchemy.orm import relationship
from .database import Base

class Patient(Base):
    __tablename__ = "patients"
    id = Column(Integer, primary_key=True, index=True)
    patient_code = Column(String, unique=True, index=True, nullable=False)
    age = Column(Integer, nullable=False)
    sex = Column(String, nullable=False)
    diagnosis = Column(String, nullable=False)
    mmse = Column(Float, nullable=False)
    moca = Column(Float, nullable=False)
    visit = Column(Integer, default=1)
    visit_date = Column(Date)
    memory = Column(Float, nullable=False)
    attention = Column(Float, nullable=False)
    executive = Column(Float, nullable=False)
    language = Column(Float, nullable=False)
    visuospatial = Column(Float, nullable=False)
    processing_speed = Column(Float, nullable=False)
    orientation = Column(Float, nullable=False)
    visits = relationship("Visit", back_populates="patient", cascade="all, delete-orphan")

class Visit(Base):
    __tablename__ = "visits"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=False)
    visit = Column(Integer, nullable=False)
    visit_date = Column(Date, nullable=False)
    mmse = Column(Float, nullable=False)
    moca = Column(Float, nullable=False)
    memory = Column(Float, nullable=False)
    attention = Column(Float, nullable=False)
    executive = Column(Float, nullable=False)
    language = Column(Float, nullable=False)
    visuospatial = Column(Float, nullable=False)
    processing_speed = Column(Float, nullable=False)
    orientation = Column(Float, nullable=False)
    patient = relationship("Patient", back_populates="visits")
