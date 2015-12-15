import os
import sys
import string

from time import sleep
from Queue import *
from threading import Thread
from functools import wraps

import MySQLdb
import requests

from flask import *

app = Flask(__name__)

limit = 50

def escape(s):
    d = {
        '\\': '\\\\',
        '\'': '\\\'',
        '\"': '\\\"'
    }
    return ''.join([d.get(c, c) for c in s])
	
# 401 auth
def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    return username == 'admin' and password == 'secret'
# 401 auth
def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

# 401 auth
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def sqlmap_scan(target):
    r = requests.get('http://127.0.0.1:8775/task/new')
    taskid = r.json()['taskid']
    url = 'http://127.0.0.1:8775/scan/%s/start' % taskid
    data = {'url': target[1] + target[2]}
    if target[3] == 1:
        data['data'] = target[4][target[4].index('\r\n\r\n')+4:]
    r = requests.post(url, data=json.dumps(data), headers={'Content-Type': 'application/json'})
    db.query("update burp set isComplete=1, taskid='%s' where id= %d" % (taskid, target[0]))


class Worker(Thread):
    def __init__(self):
        super(Worker, self).__init__()
        self.daemon = 1
        self.count = 0

    def run(self):
        try:
            while 1:
                undone = db.get_undone()
                # Get new tasks
                # Start scanning if have not reach the limit
                for target in undone:
                    if target[-2] == 0 and self.count < limit:
                        sqlmap_scan(target)
                        self.count += 1
                    # Get maybe scanning task
                    # if not in current sqlmap api scanning tasks
                    # add if have not reach limit
                    elif target[-2] == 1:
                        r = requests.get("http://127.0.0.1:8775/scan/%s/status" % target[-1])
                        if r.json().get('status'):
                            continue
                        elif self.count < limit:
                            sqlmap_scan(target)
                            self.count += 1

                scanning = db.get_scanning()

                for i in scanning:
                    r = requests.get("http://127.0.0.1:8775/scan/%s/status" % i[-1])
                    if r.json().get('status') == 'terminated':
                        # Task done
                        db.query('update burp set isComplete=2 where id=%s' % i[0])
                        r = requests.get("http://127.0.0.1:8775/scan/%s/data" % i[-1])
                        data = r.json()['data']
                        db.query(
                            'insert into result (host, url , result) values("%s", "%s", "%s")' % (
                                i[1], i[2], escape(repr(data)) if data else  'Not vuln'
                            )
                        )
                        self.count -= 1
                sleep(5)
        except Exception, e:
            print e


class MyDB:
    def __init__(self, username, password, host, db):
        self.username = username
        self.password= password
        self.host = host
        self.db = db

    def connect(self):
        try:
            conn = MySQLdb.connect(host=self.host, user=self.username, passwd=self.password, db=self.db)
            self.conn = conn
            self.cursor = conn.cursor()
        except Exception, e:
            print e
            sys.exit()

    def close(self):
        self.conn.commit()
        self.cursor.close()
        self.conn.close()

    def query(self, sql):
        self.connect()
        self.cursor.execute(sql)
        result = self.cursor.fetchall()
        self.close()
        return result

    def get_all(self):#
        return self.query('select * from burp')

    def get_scanning(self):
        return self.query('select * from burp where isComplete = 1')

    def get_new(self):
        return self.query('select * from burp where isComplete = 0')

    def get_done(self):
        return self.query('select * from burp where isComplete = 2')

    def get_undone(self):
        return self.query('select * from burp where isComplete != 2')


db = MyDB('root', 'root', 'localhost', 'sqlmap')


@app.route('/')
@app.route('/index/')
@requires_auth
def start():
    alldata = db.get_all()
    for i in alldata:
        print i
    return render_template('index.html', res=alldata)


@app.route('/result/')
@requires_auth
def vul():
    alldata = db.query('select * from result')
    return render_template('result.html', res=alldata)


if __name__ == '__main__':
    worker = Worker()
    worker.start()
    app.run(port=5000,debug=False)
