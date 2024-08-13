from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy import Enum
import enum

# Create enums for role
class Role(enum.Enum):
    ADMIN = 'admin'
    SPONSOR = 'sponsor'
    INFLUENCER = 'influencer'

# Create enums for status
class Status(enum.Enum):
    PENDING = 'pending'
    ACCEPTED = 'accepted'
    REJECTED = 'rejected'
    COMPLETED = 'completed'
    INFLUENCER_COUNTER = 'influencer_counter'
    SPONSOR_COUNTER = 'sponsor_counter'
    ACTIVE = 'active'
    INACTIVE = 'inactive'

class Visibility(enum.Enum):
    PUBLIC = 'public'
    PRIVATE = 'private'

db = SQLAlchemy()

rejected_requests = db.Table('rejected_requests',
    db.Column('user_id', db.Integer, db.ForeignKey('user.user_id'), primary_key=True),
    db.Column('request_id', db.Integer, db.ForeignKey('ad_request.request_id'), primary_key=True)
)

class User(db.Model, UserMixin):
    user_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)
    role = db.Column(Enum(Role), nullable=False)
    image = db.Column(db.String(255), default='profile.png')
    signup_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    niche = db.Column(db.String(100))
    platform = db.Column(db.String(100))
    reach = db.Column(db.Integer)
    flagged = db.Column(db.Boolean, nullable=False, default=False)

    campaigns = db.relationship('Campaign', backref='user', lazy=True)
    sent_ad_requests = db.relationship('AdRequest', foreign_keys='AdRequest.sender_id', backref='sender', lazy=True)
    received_ad_requests = db.relationship('AdRequest', foreign_keys='AdRequest.receiver_id', backref='receiver', lazy=True)
    
    rejected_requests = db.relationship('AdRequest', secondary=rejected_requests, lazy='subquery',
                                        backref=db.backref('rejected_by', lazy=True))

    def get_id(self):
        return self.user_id

    def __repr__(self):
        return f"User('{self.name}', '{self.email}', '{self.role.name}')"

class Campaign(db.Model):
    campaign_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    budget = db.Column(db.Float, nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    visibility = db.Column(Enum(Visibility), nullable=False)
    status = db.Column(Enum(Status), nullable=False)
    flagged = db.Column(db.Boolean, nullable=False, default=False)
    niche = db.Column(db.String(100), nullable=False, default="")

    ad_requests = db.relationship('AdRequest', backref='campaign', cascade='all, delete-orphan', lazy=True)

    def __repr__(self):
        return f"Campaign('{self.title}', '{self.budget}', '{self.start_date}', '{self.end_date}')"

class AdRequest(db.Model):
    request_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(Enum(Status), nullable=False, default=Status.PENDING.name)
    deadline = db.Column(db.DateTime, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.user_id'))
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.campaign_id', ondelete='CASCADE'), nullable=False)

    def __repr__(self):
        return f"AdRequest('{self.title}', '{self.amount}', '{self.status.name}')"


