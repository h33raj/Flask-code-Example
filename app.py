from flask import render_template, flash
from flask import Flask, render_template, json,request

app = Flask(__name__)
app.secret_key = 'flag{blah_blah_blah}'

@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/")
def main():
    return render_template('index.html')

@app.route('/showSignUp')
def showSignUp() :
    return render_template('signup.html')

@app.after_request
def security_Headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    #response.headers["Cache-Control"] = "post-check=0, pre-check=0, false"
    return response

if __name__ ==   "__main__": 
    app.run()
