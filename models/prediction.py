from models import db

class Prediction(db.Model):
    __tablename__ = 'predictions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    hash_value = db.Column(db.Text)
    time = db.Column(db.String(100))
    hash_len = db.Column(db.Integer)
    prediction = db.Column(db.Text)

    user = db.relationship('User', back_populates='predictions')
