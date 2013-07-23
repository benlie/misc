#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import webapp2
import logging
import jinja2
from google.appengine.api import memcache
from google.appengine.ext import db

import os
import re
import hmac
import time
import random
import string
import hashlib
import calendar
import datetime

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

##############################################################################################################
##
##	db mappers / records
##
##############################################################################################################


class WikiUserAccount(db.Model):
    name  = db.StringProperty(required = True)
    pwd   = db.StringProperty(required = True)
    email = db.StringProperty()

class WikiPage(db.Model):
    path    = db.StringProperty(required = True)
    content = db.TextProperty()
    last_modification = db.DateTimeProperty(auto_now_add = True)

class WikiPageHistory(db.Model):
    page_key  = db.IntegerProperty(required = True)
    content   = db.TextProperty()
    version   = db.StringProperty(required = True)
    timestamp = db.IntegerProperty(required = True)


##############################################################################################################
##
##	handlers
##
##############################################################################################################

##############################################################################################################
# decorators and base classes
##############################################################################################################

def check_signed_in(mthd):
    """
    decorator to check if user is logged in prior to the execution of the method
    """
    def _mthd(self, *args, **kwargs):
	usr = str(self.request.cookies.get('user_id'))
	usr = check_secure_val(usr)
	if usr:
	    return mthd(self, *args, signed_in = True, usr = usr, **kwargs)
	else:
	    return mthd(self, *args, **kwargs)
    return _mthd

def render_header(render):
    """
    decorator to automate header rendering
    """
    def _render(self, *args, **kwargs):
	JinjaHandler.render(self, 'header.html', **kwargs)
	render(self, *args, **kwargs)
	JinjaHandler.write(self, '\n  </body>\n</html>')
    return _render

class JinjaHandler(webapp2.RequestHandler):
    """
    parent class which implements the use of jinja to render a page
    all subsequent classes derive from it
    cannot be used directly
    """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kwargs):
        t = jinja_env.get_template(template)
        self.write(t.render(kwargs))

    def get(self):
	pass


##############################################################################################################
# pages part
##############################################################################################################

class MainHandler(JinjaHandler):
    """
    Handles the main page with instructions
    """
    @check_signed_in
    def get(self, **kwargs):
	self.render("main.html", **kwargs)


class PageHandler(MainHandler):
    """
    handler of the default view of the wiki
    """
    def get(self, page_id = '', **kwargs):
	page_exists, page = get_wiki_page(page_id)
	if page_exists:
	    self.render('page.html', page=page)
	else:
	    self.redirect('/wiki/edit/' + page_id)	    

    @check_signed_in
    @render_header
    def render(self, template, **kwargs):
	JinjaHandler.render(self, template, **kwargs)


class EditHandler(JinjaHandler):
    """
    handler of the edition part of the wiki
    """
    @check_signed_in
    def get(self, page_id = '', **kwargs):
	page_exists, page = get_wiki_page(page_id)

	if kwargs.get('signed_in', False):
	    self.render('edit.html', page=page, **kwargs)
	else:
	    if page_exists:
		self.no_auth_error(page = page, **kwargs)
	    else:
		self.no_page_error(page = page, **kwargs)

    def no_page_error(self, **kwargs):
	self.render('page.html', page_error = "This page does not exist. Sign in to create it !", **kwargs)

    def no_auth_error(self, **kwargs):
	self.render('page.html', page_error = "Sign in to modify this page !", **kwargs)

    @render_header
    def render(self, template, **kwargs):
	JinjaHandler.render(self, template, **kwargs)

    @check_signed_in
    def post(self, page_id = '', **kwargs):
	if kwargs.get('signed_in', False):
	    page_content = self.request.get('content')
	    put_wiki_page(page_id, page_content)
	    self.redirect('/wiki/page/' + page_id)
	else:
	    self.redirect('/wiki/edit/' + page_id)


class ArchiveHandler(PageHandler):
    """
    handler of the older versions of a page
    """
    def get(self, page_id = '', **kwargs):
	version = self.request.get('version', None)
	if version:
	    page_exists, page = get_page_archive(page_id, version)
	    if page_exists:
		self.render('page.html', page=page, **kwargs)
	    else:
		self.redirect('/wiki/history/' + page_id)
	else:
	    self.redirect('/wiki/page/' + page_id)


class HistoryHandler(PageHandler):
    """
    handler of the history of a page
    """
    def get(self, page_id = '', **kwargs):
	history = get_page_history(page_id)
	if history:
	    page = history[0]
	    del history[0]
	    self.render("history.html", page=page, history=enumerate(history), **kwargs)
	else:
	    self.redirect('/wiki/edit/' + page_id)


##############################################################################################################
# signup part
#############################################################################################################

class SignupHandler(JinjaHandler):
    """
    handles the signup part
    """
    @check_signed_in
    def get(self, **kwargs):
        self.render('signup.html', **kwargs)

    @check_signed_in
    def post(self, **kwargs):
	"""
	handles the request
	checks if username is available
	checks if the fields are correct
	escapes the data
	"""
	if kwargs.get('signed_in', False):
	    self.render('signup.html', **kwargs)
	    return

	user  = self.request.get('username')
	pwd   = self.request.get('password')
	check = self.request.get('verify')
	email = self.request.get('email')

	if self.validate(user, pwd, check, email) and saved_user_account(user, pwd, email):
	    usr_token = get_token_for(user)
	    self.response.headers.add_header('Set-Cookie', 'user_id={0}; Path=/'.format(usr_token))
	    self.redirect("/wiki")
	else:
	    self.render("signup.html", information_error = True)

    def validate(self, user, pwd, check, email):
	return (pwd == check) \
		and valid_username(user) \
		and valid_password(pwd) \
		and (valid_email(email) or email == '')


class SignoutHandler(JinjaHandler):
    """
    handles the logout part
    """
    @check_signed_in
    def get(self, **kwargs):
	if kwargs.get('signed_in', False):
	    self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
	self.redirect("/wiki")


class SigninHandler(JinjaHandler):
    """
    handles the login part
    """
    def get(self):
	self.render("signin.html")

    def post(self):
	"""checks if user exists and has correct password and rewards them with a cookie"""
	usr = self.request.get('username')
	pwd = self.request.get('password')
	if self.validate(usr, pwd):
	    if user_successfully_authenticated(usr, pwd):
		usr_token = get_token_for(usr)
		self.response.headers.add_header('Set-Cookie', 'user_id={0}; Path=/'.format(usr_token))
		self.redirect("/wiki")
	self.render("signin.html", information_error = True)

    def validate(self, usr, pwd):
	return valid_username(usr) and valid_password(pwd)


##############################################################################################################
##
##	utils
##
##############################################################################################################

##############################################################################################################
# signup/login part
##############################################################################################################

# Regexes
USER_RE = re.compile("^[a-zA-Z0-9_-]{3,20}$")
PWD_RE = re.compile("^.{3,20}$")
MAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)

def valid_password(password):
    return PWD_RE.match(password)

def valid_email(email):
    return MAIL_RE.match(email)

def get_token_for(usr):
    """
    returns auth cookie id for user
    """
    return str(make_secure_val(usr))

def username_exists(username):
    """
    checks if username not taken
    """
    candidates = db.GqlQuery("SELECT * FROM WikiUserAccount WHERE name = :1", username)
    return candidates.count(1) > 0

def saved_user_account(usr, pwd, email):
    """
    this puts a new account in the db if username is available
    """
    if not username_exists(usr):
	new_usr = WikiUserAccount(name = usr, pwd = make_pw_hash(usr, pwd), email = email)
	new_usr.put()
	return True
    return False

def user_successfully_authenticated(usr, pwd):
    """
    answers if pair is valid
    """
    if not username_exists(usr): return False

    query = db.GqlQuery("SELECT pwd FROM WikiUserAccount WHERE name = :1", usr)
    h = query.get()
    return confirm_pw_hash(usr, pwd, str(h.pwd))

##############################################################################################################
# security part
##############################################################################################################

# Hash
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '{0},{1}'.format(h, salt)

def confirm_pw_hash(name, pw, h):
    hs = h.split(',')
    return hs[0] == hashlib.sha256(name + pw + hs[1]).hexdigest()

# Hmac
SECRET = 'wikissosecretsecret'
def hash_str(s):
    H = hmac.new(SECRET, s)
    return H.hexdigest()

def make_secure_val(s):
    return '{0}|{1}'.format(s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val
    return None

##############################################################################################################
# pages part
##############################################################################################################

def get_wiki_page(page_path):
    """
    checks if page is in memcache, then the db, and returns an empty one if absent
    """
    page_data = memcache.get(page_path)
    if page_data is None:
	query = db.GqlQuery("SELECT * FROM WikiPage WHERE path = :1", page_path)
	page_data = query.get()
	memcache.set(page_path, page_data)
    if page_data is None:
	return False, WikiPage(path=page_path, content='')
    return True, page_data

def get_page_history(page_id):
    """
    returns all the versions of a page ordered from most recent to oldest
    """
    res = []
    page_exists, page = get_wiki_page(page_id)
    if page_exists:
	res.append(page)
	query = db.GqlQuery("SELECT * FROM WikiPageHistory WHERE page_key = :1 ORDER BY timestamp DESC", page.key().id())
	res.extend(q for q in query)
    return res

def get_page_archive(page_id, version):
    """
    returns a specific snapshot of a page
    """
    page_exists, page = get_wiki_page(page_id)
    if page_exists:
	query = WikiPageHistory.gql("WHERE page_key = :1 AND version = :2", page.key().id(), version)
	page  = query.get()
	if page:
	    return True, WikiPage(path=page_id,
				    content=page.content,
				    last_modification=datetime.datetime.fromtimestamp(page.timestamp))
    return False, WikiPage(path=page_id,content='')

def archive_wiki_page(page_key, page_version):
    """
    saves a page in the archive table
    """
    sha1 = hashlib.sha1('{0} : {1}'.format(page_version.path, page_version.last_modification)).hexdigest()
    archive = WikiPageHistory(page_key=page_key, 
				content=page_version.content,
				version=sha1, 
				timestamp=calendar.timegm(page_version.last_modification.utctimetuple()))
    archive.put()
    return True

def put_wiki_page(page_id, page_content):
    """
    saves modifications of a page
    """
    page_exists, page = get_wiki_page(page_id)
    if page_exists:
	archive_wiki_page(page.key().id(), page)
	page.last_modification = datetime.datetime.now()
    page.content = page_content
    page.put()
    memcache.set(page_id, page)


##############################################################################################################
##
## app section
##
##############################################################################################################


handlers = []

PAGE_NAME_RE = '((?:[a-zA-Z0-9_-]+/?)*)'

handlers.append(('/wiki/?', MainHandler))
handlers.append(('/wiki/page/' + PAGE_NAME_RE, PageHandler))
handlers.append(('/wiki/edit/' + PAGE_NAME_RE, EditHandler))
handlers.append(('/wiki/archive/' + PAGE_NAME_RE, ArchiveHandler))
handlers.append(('/wiki/history/' + PAGE_NAME_RE, HistoryHandler))
handlers.append(('/wiki/sign_in', SigninHandler))
handlers.append(('/wiki/sign_up', SignupHandler))
handlers.append(('/wiki/sign_out', SignoutHandler))

app = webapp2.WSGIApplication(handlers, debug=True)
