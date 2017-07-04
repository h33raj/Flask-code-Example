from flask import Flask, render_template_string, render_template,request, url_for
from jinja2 import Template

app = Flask(__name__)

@app.route('/')
def form():
    return render_template('form_submit.html')

@app.route('/hello/', methods=['POST'])
def hello():
    name=request.form['yourname']
    email=request.form['youremail']
    template = '''
    <div class="center-content error">
        <h1>Thank you for submitting form: </h1>
        <h3>Sender : %s</h3>
        <h3>Sender email : %s</h3>
    </div>
    ''' % (name, email)
    return render_template_string(template), 404

# Run the app :)
if __name__ == '__main__':
  app.run( 
        host="0.0.0.0",
        port=int("8000")
  )

