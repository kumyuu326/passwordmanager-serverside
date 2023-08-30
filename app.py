from crypt import methods
import os
import hashlib
import datetime
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, current_user, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True, origins='http://127.0.0.1:3000')
app.config['SQLALCHEMY_BINDS'] = {
    'db1': 'sqlite:///user.db',
    'db2': 'sqlite:///pwd.db'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = os.urandom(24)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pwd.db'

login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)

TWILIO_ACCOUNT_SID="AC348d9e64b0f5495d684d1f190ae14093"
TWILIO_AUTH_TOKEN="6c30598ed30858493be0a3b5536b76d3"
TWILIO_VERIFY_SERVICE="VAea860eefaa3d75ad2b03ef0a7c01568f"

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

#ユーザークラス
class User(UserMixin, db.Model):
  __bind_key__ = 'db1'
  id = db.Column(db.Integer, primary_key=True)
  email = db.Column(db.String(50), unique=True, nullable=False)
  ms_password = db.Column(db.String(18), nullable=False)
  def __init__(self, email, ms_password):
    self.email = email
    self.ms_password = ms_password

class AnUser(db.Model):
  __bind_key__ = 'db2'
  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer, nullable=False)
  hostname = db.Column(db.String(50))
  username = db.Column(db.String(50))
  email = db.Column(db.String(50))
  password = db.Column(db.String(18), nullable=False)
  text = db.Column(db.String)


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))

#メールの送信
def send_verification(email):
  try:
    verification = client.verify \
      .services(TWILIO_VERIFY_SERVICE) \
      .verifications \
      .create(to=email, channel='email')
    print(verification.sid)
    return 'T'
  
  except TwilioRestException as e:
    print(e)
    return 'F'

def check_verification_token(phone, token):
  check = client.verify \
    .services(TWILIO_VERIFY_SERVICE) \
    .verification_checks \
    .create(to=phone, code=token)
  return check.status == 'approved'


@app.route('/api/user_id')
def get_user_id():
    if current_user.is_authenticated:
        return jsonify(user_id=current_user.id)
    else:
        return jsonify(user_id=None)

@app.route('/', methods=['POST', 'GET'])
def top():
  return render_template('top.html')

@app.route('/Signup/email', methods=['GET','POST'])
def signup_email():
  email = None
  if request.method == 'POST':
    email = request.form.get('email')
    session['email'] = email

    send_verification(email)
    return redirect('/Signup/verifyme')


  return render_template('signup_email.html')

@app.route('/Signup/verifyme', methods=['POST', 'GET'])
def signup_generate_verification_code():
  email = session['email']
  if request.method == 'POST':
    verification_code = request.form['verificationcode']
    if check_verification_token(email, verification_code):
      return redirect('/Signup')

  return render_template('verifypage.html')

@app.route('/Signup', methods=['POST', 'GET'])
def signup():
  ms_password = None
  email = session['email']
  if request.method == 'POST':
    ms_password = request.form.get('password')
    user = User(email=email, ms_password=generate_password_hash(ms_password, method='sha256'))

    db.session.add(user)
    db.session.commit()
    user = User.query.filter_by(email=email).first()
    login_user(user)
    get_user_id()
    return redirect('/home')

  return render_template('signup.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
  email = None
  ms_password = None
  if request.method == 'POST':
    email = request.form.get('email')
    ms_password = request.form.get('password')
    session['email'] = email

    user = User.query.filter_by(email=email).first()
    if check_password_hash(user.ms_password, ms_password):
      send_verification(email)

      return redirect('/login/verifyme')
         
  return render_template('login.html')

@app.route('/login/verifyme', methods=['POST', 'GET'])
def login_generate_verification_code():
  email = session['email']
  if request.method == 'POST':
    verification_code = request.form['verificationcode']
    if check_verification_token(email, verification_code):
      user = User.query.filter_by(email=email).first()
      login_user(user)
      return redirect('/home')
  return render_template('verifypage.html')


@app.route('/home', methods=['POST', 'GET'])
@login_required
def home():
  if request.method == 'POST':
    return '0'
  
  forms = AnUser.query.filter(AnUser.user_id==current_user.id).with_entities(AnUser.id, AnUser.hostname, AnUser.email, AnUser.password).all()

  return render_template('home.html', forms=forms)

@app.route('/data', methods=['POST', 'GET'])
def data():
  if request.method == 'POST':
    user_id = request.form.get('user_id')
    hostname = request.form.get('hostname')
    username = request.form.get('email')
    password = request.form.get('password')

    print(user_id)
    print(hostname)
    print(username)
    print(password)

    form = AnUser(user_id=int(user_id), hostname=hostname, username=username, password=password)
    db.session.add(form)
    db.session.commit()

  return 'f'

@app.route('/detail/<int:id>', methods=['POST', 'GET'])
@login_required
def detail(id):
  list = AnUser.query.filter_by(id=id).one()
  return render_template('detail.html', list=list)

@app.route('/check', methods=['POST', 'GET'])
@login_required
def check():
  if request.method == 'POST':
    id = request.form["id"]
    return render_template('check.html', id=id)

@app.route('/check/password', methods=['POST', 'GET'])
@login_required
def check_pass():
  if request.method == 'POST':
    password = request.form["password"]
    id = request.form["id"]

    user = User.query.filter(User.id==current_user.id).first()

    if check_password_hash(user.ms_password, password):
      return redirect(url_for('detail', id=id))
    else:
      return '0'

@app.route('/delete', methods=['POST'])
def delete():
  if request.method == 'POST':
    id = request.form["id"]
    list = AnUser.query.filter_by(id=id).first()
    db.session.delete(list)
    db.session.commit()
    return redirect('/home')

@app.route('/update', methods=['POST', 'GET'])
@login_required
def update():
    if request.method == 'POST':
        id = request.form["id"]
        list = AnUser.query.filter_by(id=id).one()

        return render_template('update.html', list=list)

@app.route('/u', methods=['POST', 'GET'])
@login_required
def u():
    if request.method == 'POST':       
        id = request.form["id"]
        list = AnUser.query.filter_by(id=id).one()
        list.username = request.form["username"]
        list.password = request.form["password"]
        list.text = request.form["text"]

        db.session.commit()

        return redirect('/home')


if __name__=='__main__':
  app.run(debug=True)