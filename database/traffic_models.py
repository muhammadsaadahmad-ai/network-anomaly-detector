from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config2 import DATABASE_URL

Base    = declarative_base()
engine  = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

class TrafficRecord(Base):
    __tablename__ = "traffic"
    id            = Column(Integer, primary_key=True)
    timestamp     = Column(DateTime, default=datetime.utcnow)
    src_ip        = Column(String(50))
    dst_ip        = Column(String(50))
    src_port      = Column(Integer)
    dst_port      = Column(Integer)
    protocol      = Column(String(10))
    packet_size   = Column(Integer)
    flags         = Column(String(20))
    is_anomaly    = Column(Boolean, default=False)

class Alert(Base):
    __tablename__ = "alerts"
    id            = Column(Integer, primary_key=True)
    timestamp     = Column(DateTime, default=datetime.utcnow)
    alert_type    = Column(String(50))
    src_ip        = Column(String(50))
    dst_ip        = Column(String(50))
    dst_port      = Column(Integer)
    severity      = Column(String(20))
    description   = Column(String(500))
    packet_count  = Column(Integer, default=1)

def init_db():
    Base.metadata.create_all(engine)
    print("[+] Traffic database initialized.")

