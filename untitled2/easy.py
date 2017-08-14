from flask import Flask, render_template, request, redirect, jsonify, url_for, session, flash, abort, g
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from ddata import Base, Users, Events, User
from flask_sqlalchemy import SQLAlchemy
import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm.exc import NoResultFound
from flask_wtf import Form
from wtforms import SubmitField, StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, Regexp, EqualTo
from flask_wtf import FlaskForm

app = Flask(__name__)

app.config['SECRET_KEY'] = 'deVElpPasswordkey1!'
engine = create_engine('sqlite:///handler.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()
user = User()
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    name = StringField('name', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80),
                                                     EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('confirmpassword', validators=[InputRequired()])


@login_manager.user_loader
def load_user(user_id):
    return session.query(Users).get(int(user_id))


@app.route('/')
def index():
    events = session.query(Events).all()
    return render_template('landing.html', events=events)


@app.route('/home')
@login_required
def home():
    events = session.query(Events).all()
    return render_template('home.html', events=events)


@app.route('/signup/', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        hashed_password = generate_password_hash(request.form['password'], method='sha256')
        if session.query(Users).filter_by(email=request.form['email']).first():
            return ('<p>Email already registered.</p>')
        if session.query(Users).filter_by(name=request.form['name']).first():
            return ('<p>Username already exists.</p>')
        user = Users(name=request.form['name'], password=hashed_password, email=request.form['email'])
        session.add(user)
        session.commit()
        flash('User successfully registered')
        return render_template('login.html')
    return render_template('signup.html')


@app.route('/create/', methods=['GET', 'POST'])
@login_required
def createEvent():
    if request.method == 'POST':
        time = str(request.form['time']).split(':')
        time = datetime.time(int(time[0]), int(time[1]))
        date = str(request.form['date']).split('-')
        date = datetime.date(int(date[0]), int(date[1]), int(date[2]))
        events = Events(name=request.form['name'], fee=request.form['fee'], date=date, time=time,
                        location=request.form['location'],
                        organisers=request.form['organisers'], description=request.form['description'],
                        category=request.form['category'], privacy=request.form['privacy'])
        session.add(events)
        session.commit()
        return render_template('landing.html')
    return render_template('createEvent.html')


# editing event
@login_required
@app.route('/event/<int:event_id>/edit', methods=['GET', 'POST'])
def edit(event_id):
    enow = session.query(Events).filter_by(id=event_id).one()
    if request.method == 'POST':
        if request.form['name']:
            enow.name = request.form['name']
        if request.form['description']:
            enow.description = request.form['description']
        if request.form['fee']:
            enow.fee = request.form['fee']
        if request.form['category']:
            enow.category = request.form['category']
        if request.form['date']:
            enow.date = request.form['date']
        if request.form['privacy']:
            enow.privacy = request.form['privacy']
        if request.form['time']:
            enow.time = request.form['time']
        if request.form['organisers']:
            enow.organisers = request.form['organisers']
        session.add(enow)
        session.commit()
        return redirect(url_for('myEvents'))

    else:
        return render_template('editevent.html')

# log in page
@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usernam = request.form['username']
        passw = request.form['password']
        try:
            usernw = session.query(Users).filter_by(email=usernam).first()
            if check_password_hash(usernw.password, request.form['password']):
                login_user(usernw)
                flash('Logged in successfully')
                return redirect(url_for('home'))
        except NoResultFound:
            flash('Invalid Credentials')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/myEvents/')
@login_required
def myEvents():
    events = session.query(Events).filter_by(register_id = user.get_id() )
    return render_template('myEvents.html', events=events)


# logging out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return ('<p>logged out</p>')


if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
