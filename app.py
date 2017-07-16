import os
import re
import base64
from datetime import datetime
from OpenSSL import SSL, rand
from flask import escape, session
from flask_sqlalchemy import SQLAlchemy
from flask import render_template, flash
from werkzeug.utils import secure_filename
from flask import url_for,send_from_directory
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask import Flask, render_template,request, redirect
from flask_login import login_user, LoginManager, UserMixin, logout_user, login_required

#Intialize the flask application
app = Flask(__name__)
app.secret_key = base64.b64encode(rand.bytes(128)) 
#To Register CSRF protection globally for the app
csrf = CSRFProtect()
csrf.init_app(app)

#Instantiating Flask Login
login_manager = LoginManager()
login_manager.init_app(app)

#Configurations
#Strictly protection on SSL, Referrer
app.config['WTF_CSRF_SSL_STRICT'] = True 
#A random string for generating CSRF token
app.config['WTF_CSRF_SECRET_KEY'] = base64.b64encode(rand.bytes(128)) 

#The path to the upload directory
app.config['UPLOAD_FOLDER'] = 'uploads/'
#Extensions which are accepted to be uploaded
app.config['ALLOWED_EXTENSIONS'] = set(['png', 'jpg', 'jpeg', 'pdf'])

"""
This function is where you store all your input validation controls. 
It makes it easy to maintain whenever you want to apply changes for 
certain input validation roles and reduces the chance of mistakes in your regexes.
"""

#Will track modifications of objects and emit signals
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
#Database URI is used for connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
#Create object of SQL Alchemy
db = SQLAlchemy(app)

def checkPassword(pwd):
    error = []
    proceed = True
    #Recommended a longer password for Security
    if(len(pwd) < 8):
        error.append("Password is too Short!!")
        proceed = False
    
    """
    The password should include at least one number, a small letter, a CAPS,
    and a special character as defined in the patterns array:
    """
    if not any(x.isupper() for x in pwd):
        error.append('Your password needs at least 1 capital letter')
    if not any(x.islower() for x in pwd):
        error.append('Your password needs at least 1 small letter')
    if not any(x.isdigit() for x in pwd):
        error.append('Your password needs at least 1 digit')

    """
    Even though your password is sufficient according to all your standards, the password could still be weak.
    Just imagine the password "Password!"; this could easily be guessed by an attacker. To prevent the use of weak passwords we 
    compare the password with a list of top 500 bad passwords and if matched, the password wil be rejected:
    """

    file = open('badpasswords.txt').read()
    pattern = file.split(",") 

    for value in pattern:
        if value != pwd:
            pass
        else:
            error.append("Your password was matched with the bad password list, please try again.")
            proceed = False
            break

    if proceed == True:
        flash("Your password is allowed!")
        return True
    else:
        flash("Password validation failure(your choise is weak):")
        for x in error:
            print x
        return False

"""
    This is the encoder class for whenever you have to allow certain
    possibly dangerous characters into your code for i.e names such as O'reily
"""

def encoder(allowed, input, count):
    """
        As you can see you can specify allowed characters in your function
    """
    flag = True
    match = re.findall("/^[a-zA-Z0-9 " + allowed+"]+$/", input)
    if match:
        """
        Set a log for whenever there is unexpected userinput with a threat level
        See "audit logs" code example for more information:
        """
        setLog(session['id'], "Bad userinputssss", "FAIL", datetime.utcnow(), "HIGH")
        """
        Set counter if counter hits 3 the users session must terminated
        After 3 session terminations the user account must be blocked
        See "audit logs" code example for more information:
        """
        counter.increment()
        flag = False
        return escape(input)

"""
    First we create a function which checks the allowed patterns:
        checkpattern("value1,value2,value3" , $input, "3")
"""

def whitelisting(allowed, input, count):
    result = allowed.split(',')
    flag = False
    for x in result:
        match = re.findall("/^"+x+"$/", input)
        if match:
            #If the value is valid we send a log to the logging file
            setLog(session["id"], "Good whitelist validation", "SUCCESS", datetime.utcnow(),"HIGH")
            flag = True
            #Whenever there was a valid match we return true
            return True
        #Check for a false in order to send error to log and counter the user
        if flag == False:
            setLog(session["id"], "Bad whitelist validation", "FAIL", datetime.utcnow(), "HIGH")            
            counter.increment()
            return False     

def inputValidation(type, value):
    switcher = {
        "alphanumeric": "^[a-zA-Z0-9]+$",
        "nummeric": "^[0-9]*$",
        "bool": "^(true|false)$"
    }
    pattern = switcher.get(type, "nothing")
    match = re.findall(pattern, value)
    if match:
        return True
    else:
        raise False


#Check whether the file can be uploaded
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

#File upload route
@app.route('/upload', methods=['POST'])
def upload_file():
    # Check if the post request has the file part
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    # Get the name of the uploaded file
    file = request.files['file']
    # Submit a empty part without filename
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    # Check if the file is one of the allowed types/extensions
    if file and allowed_file(file.filename):
        # Make the filename safe, remove unsupported chars
        filename = secure_filename(file.filename)
        # Move the file form the temporal folder to
        # the upload folder we setup
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        # Redirect the user to the uploaded_file route, which
        # will basicaly show on the browser the uploaded file
        return redirect(url_for('uploaded_file', filename=filename))
    else:
        flash('Not allowed extensions')
        return redirect(request.url)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@login_required
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/upload")
def upload():
    return render_template('file_upload.html')
"""
@app.route('/')
def index():
    return escape("<html></html>")
"""

@app.route("/")
def main():
    return render_template('index.html')

@app.route('/showSignUp')
def showSignUp() :
    return render_template('signup.html')

@app.route('/signUp', methods=['POST'])
def signUp():
    return render_template('signup.html')

@app.after_request
def security_Headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    #response.headers["Cache-Control"] = "post-check=0, pre-check=0, false"
    return response

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400

@app.route('/xss', methods=['GET', 'POST'])
def xss():
    if request.method == 'GET':
        return render_template('xss.html')
    return render_template('xss.html', user=request.form['xss'])

class privileges(db.Model):
    __tablename__ = "privileges"
    id = db.Column(db.Integer , primary_key=True)
    privilege = db.Column('privilege', db.String(20), unique=False, index=True)

    def __init__(self, privilege):
        self.privilege = privilege

class User(db.Model):
    __tablename__ = "users"
    id = db.Column('user_id',db.Integer , primary_key=True)
    username = db.Column('username', db.String(20), unique=True , index=True)
    password = db.Column('password' , db.String(10))
    email = db.Column('email',db.String(50),unique=True , index=True)
    status = db.Column('status', db.String(50), index=True)
    registered_on = db.Column('registered_on' , db.DateTime)
    privilegeID = db.Column('privilegeID', db.Integer, db.ForeignKey('privileges.id'))
 
    def __init__(self , username ,password , email, privilegeID, status):
        self.username = username
        self.password = password
        self.email = email
        self.registered_on = datetime.utcnow()
        self.privilegeID = privilegeID
        self.status = status

    def is_authenticated(self):
        return True
 
    def is_active(self):
        return True
 
    def is_anonymous(self):
        return False
 
    def get_id(self):
        return unicode(self.id)
 
    def __repr__(self):
        return '<User %r>' % (self.username)

class Counter(db.Model):
    __tablename__ = "counter"
    count = db.Column(db.Integer, nullable=False)
    blocker = db.Column(db.Integer, nullable=False)
    userID = db.Column('userID', db.Integer, db.ForeignKey('users.user_id'), primary_key=True)

    def __init__(self, count, blocker, userID):
        self.count = count 
        self.blocker = blocker
        self.userID = userID

    def increment(self):
        self.count+= self.count
        self.blocker+= self.blocker

        if self.counter >= 3:
            setLog(self.userId,"The users session was terminated", "SUCCESS", datetime.utcnow(), "NULL")
            self.count = 0
            logout()

        if self.blocker >= 12:
            setLog(self.userId,"The users is denied access to system", "SUCCESS", datetime.utcnow(), "NULL")
            user = User.query.filter_by(id=self.userID).first()
            user.status = 'Blocked'

db.create_all()

#Uncomment when the app is installed, after that comment
"""
permission = ['edit:read:delete','edit:read', 'read']
for x in permission:
    privilege = privileges(x)
    db.session.add(privilege)
    db.session.commit()
"""

def userRegister(username, password, email, privilegeID, status):
    user = User(username, password, email, privilegeID, status)
    db.session.add(user)
    db.session.commit()

#Register a user
@app.route('/register' , methods=['GET','POST'])
def register():
    if request.method == 'GET':
        return render_template('signup.html')
    userRegister(request.form['inputName'] , request.form['inputPassword'],request.form['inputEmail'], 3, "Active")
    flash('User successfully registered')
    return redirect(url_for('login'))

def setLog(userId, error, value, date, threat):
    file = "restrictedfolder/logfile.txt"
    f = open(file, 'w+')
    f.write(date + str(userId) + error + value + threat)
    f.close()

#Login a user
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form['inputName']
    password = request.form['inputPassword']
    if inputValidation('alphanumeric', username) != True:
                setLog(0, "invalid expected input", "FAIL", str(datetime.utcnow()), "HIGH");
                return redirect(url_for('login'))
    registered_user = User.query.filter_by(username=username, password=password).first()
    if registered_user is None:
        flash('Username or Password is invalid' , 'error')
        return redirect(url_for('login'))
    #Logged In Successfully
    login_user(registered_user)
    flash('Logged in successfully')
    counter = Counter(0, 0, registered_user.id)
    session['id'] = registered_user.id
    return render_template('home.html', user=request.form['inputName'])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

#Logout a user
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return render_template('index.html')    

if __name__ ==    "__main__": 
    app.run()
