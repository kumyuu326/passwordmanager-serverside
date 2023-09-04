from crypt import methods
import os
import hashlib
import datetime
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from sqlalchemy import asc, desc
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, current_user, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app, supports_credentials=True, origins='*')
app.config['SQLALCHEMY_BINDS'] = {
    'db1': 'sqlite:///user.db',
    'db2': 'sqlite:///pwd.db',
    'db3': 'sqlite:///url.db'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = os.urandom(24)

login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)

TWILIO_ACCOUNT_SID="AC348d9e64b0f5495d684d1f190ae14093"
TWILIO_AUTH_TOKEN="51f5bd31bd028d158c6ab1fab078c445"
TWILIO_VERIFY_SERVICE="VA343ff244cecc0a29777da461e2f118ee"

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

class Url(db.Model):
  __bind_key__ = 'db3'
  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer, nullable=False)
  hostname = db.Column(db.String(50))
  pin = db.Column(db.String)


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
  
  forms = Url.query.filter(Url.user_id == current_user.id).order_by(asc("pin")).all()

  for form in forms:
    print(form.pin)

  return render_template('home.html', forms=forms)

@app.route('/pin', methods=['POST', 'GET'])
@login_required
def pin():
  if request.method == 'POST':
    hostname = request.form["pin"]
    item = Url.query.filter(Url.hostname==hostname, Url.user_id==current_user.id).all()
    for i in item:
      if i.pin == 'f':
        i.pin = 'a'
        db.session.commit()
      else:
        i.pin = 'f'
        db.session.commit()
    

    return redirect('/home')

@app.route('/data', methods=['POST', 'GET'])
def data():
  if request.method == 'POST':
    user_id = request.form.get('user_id')
    hostname = request.form.get('hostname')
    username = request.form.get('email')
    password = request.form.get('password')
    pin = 'f'

    print(user_id)
    print(hostname)
    print(username)
    print(password)

    form = AnUser(user_id=int(user_id), hostname=hostname, username=username, password=password)
    db.session.add(form)
    db.session.commit()

    add_unique_data(hostname, user_id)

  return 'f'

def add_unique_data(hostname, user_id):
    existing_data = Url.query.filter(Url.user_id==user_id, Url.hostname==hostname).first()
    if existing_data:
        print('0')
    else:
        form2 = Url(user_id=int(user_id), hostname=hostname)
        db.session.add(form2)
        db.session.commit()

@app.route('/detail/<hostname>', methods=['POST', 'GET'])
@login_required
def detail(hostname):
  list = AnUser.query.filter_by(hostname=hostname).all()
  return render_template('detail.html', list=list)

@app.route('/check', methods=['POST', 'GET'])
@login_required
def check():
  if request.method == 'POST':
    hostname = request.form["hostname"]
    return render_template('check.html', hostname=hostname)

@app.route('/check/password', methods=['POST', 'GET'])
@login_required
def check_pass():
  if request.method == 'POST':
    password = request.form["password"]
    hostname = request.form["hostname"]

    user = User.query.filter(User.id==current_user.id).first()

    if check_password_hash(user.ms_password, password):
      return redirect(url_for('detail', hostname=hostname))
    else:
      return 'パスワードが違います'

@app.route('/delete', methods=['POST'])
def delete():
  if request.method == 'POST':
    id = request.form["id"]
    list = AnUser.query.filter_by(id=id).first()
    db.session.delete(list)
    db.session.commit()

    list2 = AnUser.query.filter(AnUser.hostname==list.hostname, AnUser.user_id==current_user.id).all()
    if(list2 is None):
      list3 = Url.query.filter(Url.hostname==list.hostname, Url.user_id==current_user.id).first()
      db.session.delete(list3)
      db.session.commit()
    else:
      print('まだ情報が存在します')

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