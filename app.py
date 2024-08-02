from flask import Flask, render_template, request, url_for, flash, redirect, session
from ldap3 import Connection, Server
from ldap3 import SIMPLE, SUBTREE
from ldap3.core.exceptions import LDAPBindError, LDAPConstraintViolationResult, \
  LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError, \
  LDAPSocketOpenError, LDAPExceptionError
from ldap3 import ALL_ATTRIBUTES, MODIFY_REPLACE, NTLM, ALL_OPERATIONAL_ATTRIBUTES
import json
from pathlib import Path
import shutil
import yaml


def read_config():
  with open('config.yaml') as f:
    return yaml.safe_load(f)

config = read_config()  

LDAP_SERVER = config["LDAP_SERVER"]
LDAP_PORT = config["LDAP_PORT"]
LDAP_BASE = config["LDAP_BASE"]
LDAP_SEARCH = config["LDAP_SEARCH"]
LDAP_ADMIN= config["LDAP_ADMIN"]
LDAP_ADMIN_PWD= config["LDAP_ADMIN_PWD"]
AD_DOMAIN = config["AD_DOMAIN"]
OBJECT_CLASS = ['top', 'person', 'organizationalPerson', 'user']


def connect_ldap(ssl=False, **kwargs):
  server = Server(host=LDAP_SERVER,  use_ssl=ssl, connect_timeout=25)
    
  return Connection(server, raise_exceptions=True, **kwargs)


def get_attributes(username):
  return {
    "displayName": username,
    "sAMAccountName": username,
    "userPrincipalName": "{}@{}".format(username,AD_DOMAIN),
    "name": username
  }
    

def get_dn(username):
  return "CN={},".format(username) + LDAP_BASE
    

def format_username(user):
  return user + '@' + AD_DOMAIN

  
def find_user_dn(conn, uid):
  search_filter = LDAP_SEARCH.replace('{uid}', uid)
  conn.search(LDAP_BASE, "(%s)" % search_filter, SUBTREE)
  return conn.response[0]['dn'] if conn.response else None
  
  
def authenticate(username, passwd):
  user = format_username(username)
  try:
    with connect_ldap(authentication=SIMPLE, user=user, password=passwd) as conn:
      conn.bind()
      return True
  except (LDAPBindError, LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError) as ex:
    print(repr(ex))
    return False
  

def change_password(username, old_pwd, new_pwd, local=True):
  user = format_username(username)
  try:
    with connect_ldap(authentication=SIMPLE, user=user, password=old_pwd) as conn:
      conn.bind()
      user_dn = find_user_dn(conn, username)
      conn.extend.microsoft.modify_password(user_dn, new_pwd, old_pwd)
  except (LDAPBindError, LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError):
    raise Exception('Username or password is incorrect!')

  except LDAPConstraintViolationResult as e:
    # Extract useful part of the danger message (for Samba 4 / AD).
    msg = e.message.split('check_password_restrictions: ')[-1].capitalize()
    raise Exception(msg)

  except LDAPSocketOpenError as e:
    raise Exception('Unable to connect to the remote server. {}'.format(repr(e)))

  except LDAPExceptionError as e:
    raise Exception('Encountered an unexpected danger while communicating with the remote server {}'.format(repr(e)))
    
def create_user(username, new_password):
  try:
    bind_user =  format_username(LDAP_ADMIN)
    with connect_ldap(ssl=True, authentication=SIMPLE, user=bind_user, password=LDAP_ADMIN_PWD, auto_bind=True) as conn:
      attributes = get_attributes(username)
      user_dn = get_dn(username)
      result = conn.add(dn=user_dn, object_class=OBJECT_CLASS, attributes=attributes)
      if not result:
        msg = "ERROR: User '{0}' was not created: {1}".format( username, conn.result.get("description"))
        raise Exception(msg)

      # unlock and set password
      conn.extend.microsoft.unlock_account(user=user_dn)
      conn.extend.microsoft.modify_password(user=user_dn, new_password=new_password, old_password=None)
      # Enable account - must happen after user password is set
      enable_account = {"userAccountControl": (MODIFY_REPLACE, [512])}
      conn.modify(user_dn, changes=enable_account)
  except (LDAPBindError, LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError) as e:
    raise Exception('Erro de autenticacao {}'.format(repr(e)))

  except LDAPConstraintViolationResult as e:
    # Extract useful part of the danger message (for Samba 4 / AD).
    msg = e.message.split('check_password_restrictions: ')[-1].capitalize()
    raise Exception(msg)

  except LDAPSocketOpenError as e:
    raise Exception('Unable to connect to the remote server. {}'.format(repr(e)))

  except LDAPExceptionError as e:
    raise Exception('Encountered an unexpected danger while communicating with the remote server {}'.format(repr(e)))


def search_users(user=None):
  try:
    bind_user =  format_username(LDAP_ADMIN)
    _filter = "(objectclass=person)" if user is None else "(sAMAccountName={})".format(user)
    with connect_ldap(ssl=True, authentication=SIMPLE, user=bind_user, password=LDAP_ADMIN_PWD, auto_bind=True) as conn:
      conn.search(LDAP_BASE, _filter,attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
      return conn.entries
  except (LDAPBindError, LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError) as e:
    raise Exception('Erro de autenticacao {}'.format(repr(e)))

  except LDAPConstraintViolationResult as e:
    # Extract useful part of the danger message (for Samba 4 / AD).
    msg = e.message.split('check_password_restrictions: ')[-1].capitalize()
    raise Exception(msg)

  except LDAPSocketOpenError as e:
    raise Exception('Unable to connect to the remote server. {}'.format(repr(e)))

  except LDAPExceptionError as e:
    raise Exception('Encountered an unexpected danger while communicating with the remote server {}'.format(repr(e)))
      

def user_dict(entry):
    str_entry = entry.entry_to_json()
    values = json.loads(str_entry)
    ret = {}
    ret['dn'] = values['dn']
    for key in values['attributes'].keys():
        if key in values['attributes']:
            ret[key] = values['attributes'][key][0]
        else:
            ret[key] = None
        
    tmp = { key: ret[key] for key in sorted(ret.keys()) }
    
    return tmp #OrderedDict(tmp)
  
def create_home(username):
  _path = "/home/{}".format(username)
  p = Path(_path)
  if not p.exists():
    p.mkdir(parents=True)
  shutil.chown(_path, user=username, group="nogroup")


app = Flask(__name__)
app.config['SECRET_KEY'] = config["SECRET_KEY"]

def check_authentication():
    if not 'user' in session:
        flash('Usuario nao conectado!', 'danger')
        return redirect(url_for('login'))

@app.route('/', methods=('GET', 'POST'))
def login():
  if request.method == 'POST':
    user = request.form['user']
    password = request.form['password']
    res = authenticate(user, password)
    if res:
      session['user'] = user
      flash('Autenticado com exito', 'success')
      return redirect(url_for('home', user = user))
    else:
      flash('Falha na autenticacao', 'danger')

  return render_template('login.html')


@app.route('/user/<user>')
def home(user):
  check_authentication()
  return render_template('home.html', user = user)
  

@app.route('/password/<user>', methods=('GET', 'POST'))
def password(user):
  check_authentication()
  if request.method == 'POST':
    old_password = request.form['old_password']
    new_password1 = request.form['new_password1']
    new_password2 = request.form['new_password2']
    if new_password1 != new_password2:
      flash('As novas senhas nao conferem', 'danger')
    else:
      try:
        change_password(user, old_password, new_password1)
        flash('Alteracao concluida', 'success')
        return redirect(url_for('home', user = user))
      except Exception as e:
        flash(str(e), 'danger')
        
  return render_template('password.html', user = user)
  
  
@app.route('/newuser/', methods=('GET', 'POST'))
def newuser():
  check_authentication()
  if request.method == 'POST':
    new_user = request.form['user']
    new_password = request.form['password']
    try:
      create_user(new_user, new_password)
      create_home(new_user)
      flash('Criacao concluida', 'success')
    except Exception as e:
      flash(str(e), 'danger')
  return render_template('newuser.html', user = session['user'])


@app.route('/list/')
def list():
  check_authentication()
  try:
    entries = search_users(None)
  except Exception as e:
    flash(str(e), 'danger')
    entries = None
  return render_template('list.html', entries = entries)


@app.route('/details/<user>')
def details(user):
  check_authentication()
  try:
    entries = search_users(user)
    entry = user_dict(entries[0])
  except Exception as e:
    flash(str(e), 'danger')
    entry = None
  return render_template('details.html', user = user, entry = entry)

      
@app.route('/logout')
def logout():
  session.clear()
  flash('Usuario desconectado', 'success')
  return redirect(url_for('login'))

