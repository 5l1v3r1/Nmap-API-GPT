from flask import Flask, request, render_template
import nmap
import sqlite3
from lxml import etree
from flask_restful import Api, Resource
import re
import openai

openai.api_key = "__API__KEY__"
model_engine = "text-davinci-003"

app = Flask(__name__)
api = Api(app)

nm = nmap.PortScanner()

# User Database Implimentation


def db_connection():
    conn = None
    try:
        conn = sqlite3.connect("db.sqlite")
    except sqlite3.error as e:
        print(e)
    return conn

# administrator:zAp6_oO~t428)@,


def s_u(username):
    # Remove any characters that are not letters, numbers, or underscores
    sanitized_username = re.sub(r'[^\w]', '', username)
    # Remove any leading or trailing spaces
    sanitized_username = sanitized_username.strip()
    return sanitized_username


def s_p(password):
    # Remove any leading or trailing spaces
    sanitized_password = password.strip()
    return sanitized_password

# Index and Docx page


@app.route('/', methods=['GET'])
def home():
    return render_template("index.html")


@app.route('/doc', methods=['GET'])
def doc():
    return render_template("doc.html")

# Add Userdata


@app.route('/adduser/<auser>:<apass>/<uid>/<username>/<passwd>', methods=['POST'])
def add_user(uid, username, passwd, auser, apass):
    conn = db_connection()
    cursor = conn.cursor()
    auser1 = s_u(auser)
    apass1 = s_p(apass)
    new_id = uid
    new_user = s_u(username)
    new_passwd = s_p(passwd)
    sql1 = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ? """
    usernamecheck = cursor.execute(sql1, (auser1, apass1))
    if not usernamecheck.fetchone():
        return [{"error": "admin passwd or admin username error"}]
    else:
        sql = """INSERT INTO users (id, username, passwd) VALUES (?, ?, ?)"""
        cursor = cursor.execute(sql, (new_id, new_user, new_passwd))
        conn.commit()
    return f'["added": {[{"ID":new_id}], [{"Username":new_user}], [{"Password": new_passwd}]} ]'


@app.route('/altusername/<auser>:<apass>/<uid>/<username>', methods=['POST'])
def alt_user(uid, username, auser, apass):
    conn = db_connection()
    cursor = conn.cursor()
    new_id = uid
    new_user = s_u(username)
    auser1 = s_u(auser)
    apass1 = s_p(apass)
    sql1 = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ?"""
    usernamecheck = cursor.execute(sql1, (auser1, apass1))
    if not usernamecheck.fetchone():
        return [{"error": "admin passwd or admin username error"}]
    else:
        sql = """UPDATE users SET (username=?) WHERE id=?"""
        cursor = cursor.execute(sql, (new_user, new_id))
        conn.commit()
        return f'Updated {[{new_id : new_user}]} '


@app.route('/altpasswd/<auser>:<apass>/<username>/<passwd>', methods=['POST'])
def alt_passwd(username, passwd, auser, apass):
    conn = db_connection()
    cursor = conn.cursor()
    new_user = s_u(username)
    new_passwd = s_p(passwd)
    auser1 = s_u(auser)
    apass1 = s_p(apass)
    sql1 = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ?"""
    usernamecheck = cursor.execute(sql1, (auser1, apass1))
    if not usernamecheck.fetchone():
        return [{"error": "admin passwd or admin username error"}]
    else:
        sql = """UPDATE users SET passwd=? WHERE username=?"""
        cursor = cursor.execute(sql, (new_passwd, new_user))
        conn.commit()
        return f'Updated {[{new_user : new_passwd}]} '


@app.route('/altid/<auser>:<apass>/<uid>/<usern>', methods=['POST'])
def alt_id(uid, usern, auser, apass):
    conn = db_connection()
    cursor = conn.cursor()
    new_id = uid
    username = s_u(usern)
    auser1 = s_u(auser)
    apass1 = s_p(apass)
    sql1 = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ?"""
    usernamecheck = cursor.execute(sql1, (auser1, apass1))
    if not usernamecheck.fetchone():
        return [{"error": "admin passwd or admin username error"}]
    else:
        sql = """UPDATE users SET id=? WHERE username=?"""
        cursor = cursor.execute(sql, (new_id, username))
        conn.commit()
        return f'Updated {[{new_id : username}]} '


@app.route('/deluser/<auser>:<apass>/<uname>/<upass>', methods=['POST'])
def deluser(uname, upass, auser, apass):
    conn = db_connection()
    cursor = conn.cursor()
    username = s_u(uname)
    passwd = s_p(upass)
    auser1 = s_u(auser)
    apass1 = s_p(apass)
    sql1 = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ?"""
    usernamecheck = cursor.execute(sql1, (auser1, apass1))
    if not usernamecheck.fetchone():
        return [{"error": "admin passwd or admin username error"}]
    else:
        sql = """DELETE from users where username=? AND passwd=?"""
        cursor = cursor.execute(sql, (username, passwd))
        conn.commit()
        return f'Removed {[{"Username":username}]} '


# class altpasswd2(Resource):
#     def POST(self, username, password):
#         conn = db_connection()
#         cursor = conn.cursor()
#         new_user = request.form[username]
#         new_passwd = request.form[password]
#         sql = """UPDATE users SET passwd=? WHERE username=?"""
#         cursor = cursor.execute(sql, ( new_passwd, new_user))
#         conn.commit()
#         return f'added {cursor.lastrowid} '

# def user_auth(username, password):
#     conn = db_connection()
#     cursor = conn.cursor()
#     sql = """ SELECT COUNT(*) FROM users WHERE username = ? AND passwd = ?"""
#     usernamecheck = cursor.execute(sql, (username,password))
#     # usernamecheck = cursor.execute("SELECT COUNT(*) FROM users WHERE username = :username AND password = :password", username=username, password=password)
#     print(usernamecheck)
#     if usernamecheck is None:
#         return 400
#     else:
#         return 200

def profile1(username, password, url):
    ip = url
    # Nmap Execution command
    conn = db_connection()
    cursor = conn.cursor()
    un = s_u(username)
    pa = s_p(password)
    sql = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ?"""
    usernamecheck = cursor.execute(sql, (un, pa))
    if not usernamecheck.fetchone():
        return [{"error": "passwd or username error"}]
    else:
        nm.scan('{}'.format(ip), arguments='-Pn -sV -T4 -O -F')
        json_data = nm.analyse_nmap_xml_scan()
        return json_data


def profile2(username, password, url):
    ip = url
    # Nmap Execution command
    conn = db_connection()
    cursor = conn.cursor()
    un = s_u(username)
    pa = s_p(password)
    sql = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ?"""
    usernamecheck = cursor.execute(sql, (un, pa))
    if not usernamecheck.fetchone():
        return [{"error": "passwd or username error"}]
    else:
        nm.scan('{}'.format(ip), arguments='-Pn -T4 -A -v')
        json_data = nm.analyse_nmap_xml_scan()
        return json_data


def profile3(username, password, url):
    ip = url
    # Nmap Execution command
    conn = db_connection()
    cursor = conn.cursor()
    un = s_u(username)
    pa = s_p(password)
    sql = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ?"""
    usernamecheck = cursor.execute(sql, (un, pa))
    if not usernamecheck.fetchone():
        return [{"error": "passwd or username error"}]
    else:
        nm.scan('{}'.format(ip), arguments='-Pn -sS -sU -T4 -A -v')
        json_data = nm.analyse_nmap_xml_scan()
        return json_data


def profile4(username, password, url):
    ip = url
    # Nmap Execution command
    conn = db_connection()
    cursor = conn.cursor()
    un = s_u(username)
    pa = s_p(password)
    sql = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ?"""
    usernamecheck = cursor.execute(sql, (un, pa))
    if not usernamecheck.fetchone():
        return [{"error": "passwd or username error"}]
    else:
        nm.scan('{}'.format(ip), arguments='-Pn -p- -T4 -A -v')
        json_data = nm.analyse_nmap_xml_scan()
        return json_data


def profile5(username, password, url):
    ip = url
    # Nmap Execution command
    conn = db_connection()
    cursor = conn.cursor()
    un = s_u(username)
    pa = s_p(password)
    sql = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ?"""
    usernamecheck = cursor.execute(sql, (un, pa))
    if not usernamecheck.fetchone():
        return [{"error": "passwd or username error"}]
    else:
        nm.scan('{}'.format(
            ip), arguments=' {} -Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln')
        json_data = nm.analyse_nmap_xml_scan()
        return json_data


def profile_gpt(username, password, url):
    ip = url
    # Nmap Execution command
    conn = db_connection()
    cursor = conn.cursor()
    un = s_u(username)
    pa = s_p(password)
    sql = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ?"""
    usernamecheck = cursor.execute(sql, (un, pa))
    if not usernamecheck.fetchone():
        return [{"error": "passwd or username error"}]
    else:
        nm.scan('{}'.format(ip), arguments='-Pn -sV -T4 -O -F')
        json_data = nm.analyse_nmap_xml_scan()
        analize = json_data["scan"]
        # Prompt about what the quary is all about
        prompt = "do a vulnerability analysis of {} and return a vulnerabilty report in json".format(
            analize)
        # A structure for the request
        completion = openai.Completion.create(
            engine=model_engine,
            prompt=prompt,
            max_tokens=1024,
            n=1,
            stop=None,
        )
        response = completion.choices[0].text
        return response


# Effective  Scan
class p1(Resource):
    def get(self, username, password, url):
        # ip = url
        # # Nmap Execution command
        # conn = db_connection()
        # cursor = conn.cursor()
        # sql = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ?"""
        # usernamecheck = cursor.execute(sql, (username,password))
        # if not usernamecheck.fetchone():
        #     return [{"error":"passwd or username error"}]
        # else:
        #     # nm.scan('{}'.format(ip), arguments='-Pn -sV -T4 -O -F')
        #     # json_data = nm.analyse_nmap_xml_scan()
        #     return json_data
        scan = profile1(username, password, url)
        return scan

# Simple Scan


class p2(Resource):
    def get(self, username, password, url):
        scan = profile2(username, password, url)
        return scan


# Low Power Scan
class p3(Resource):
    def get(self, username, password, url):
        scan = profile3(username, password, url)
        return scan

# partial Intense Scan


class p4(Resource):
    def get(self, username, password, url):
        scan = profile4(username, password, url)
        return scan

# Complete Intense scan


class p5(Resource):
    def get(self, username, password, url):
        scan = profile5(username, password, url)
        return scan


class p1test(Resource):
    def get(self, username, password, url):
        scan = profile_gpt(username, password, url)
        return scan


api.add_resource(
    p1, "/api/p1/<string:username>:<string:password>/<string:url>")
api.add_resource(
    p1test, "/api/gpt/<string:username>:<string:password>/<string:url>")
api.add_resource(
    p2, "/api/p2/<string:username>:<string:password>/<string:url>")
api.add_resource(
    p3, "/api/p3/<string:username>:<string:password>/<string:url>")
api.add_resource(
    p4, "/api/p4/<string:username>:<string:password>/<string:url>")
api.add_resource(
    p5, "/api/p5/<string:username>:<string:password>/<string:url>")
# api.add_resource(altpasswd2, "/altpasswd2/<string:username>/<string:password>")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
