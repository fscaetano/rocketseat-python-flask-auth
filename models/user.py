""" 
    User class
"""

from flask_login import UserMixin
from database import db


class User(db.Model, UserMixin):
    """ User class

    Args:
        db: SQLAlquemy ORM base class
        UserMixin: flask_login base class
    """
    # id(int), usename(text), password(text), role(text)
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(80), nullable=False, default="user")
