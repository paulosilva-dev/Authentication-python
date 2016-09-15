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
import os
import webapp2
import jinja2
import re
from google.appengine.ext import db
import random
import string
import hashlib
import logging

# setting up jinja2
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# secret salt for userid
SECRET = "ThisAintVerySecret"

# password hashing functions
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_user_hash(userid, salt):
    return userid + '|' + hashlib.sha256(userid + salt).hexdigest()

def is_userid_valid(h):
    return h == make_user_hash(h.split('|')[0], SECRET)

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)

class User(db.Model):
    name = db.StringProperty(required=True)
    pwhash = db.StringProperty(required=True)
    email = db.StringProperty(required=False)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainHandler(Handler):
    def get(self):
        self.redirect('/signup')

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)

class signupHandler(Handler):
    def get(self):
        uname = ''
        email = ''
        self.render("signup.html", uname=uname, email=email)

    def post(self):
        # getting form data
        user = self.request.get("username")
        pw = self.request.get("password")
        pw2 = self.request.get("verify")
        email = self.request.get("email")

        # form validation :
        userValid = valid_username(user)

        # check if user exists in db
        userExists = False
        if userValid:
            users = db.GqlQuery("SELECT name FROM User")
            for usr in users:
                # debug, printing all names in db
                # logging.info("user : " + usr.name)
                if user == usr.name:
                    userExists = True

        pwValid = valid_password(pw)
        pwMatch = pw == pw2
        emailValid = True
        if email:
            emailValid = valid_email(email)
        else:
            email = ''

        # error messages
        error_name = ''
        error_name = ''
        error_password = ''
        error_verify = ''
        error_email = ''
        if not userValid:
            error_name = 'Invalid Name'
        if userExists:
            error_name = 'User name already taken'
        if not pwValid:
            error_password = 'Invalid password'
        if not pwMatch:
            error_verify = "Passwords don't match"
        if not emailValid:
            error_email = 'Invalid email'

        if userValid and pwValid and pwMatch and emailValid:
            # generate password Hash
            pwhash = make_pw_hash(user, pw)
            # save user to db
            u = User(name=user, pwhash=pwhash, email=email)
            u.put()
            # logging.info('user ' + user+ ' created')

            # set cookie
            userid = str(u.key().id())
            cookieUser = make_user_hash(userid, SECRET)

            self.response.set_cookie("user", cookieUser)
            self.redirect('welcome')
        else:
            self.render("signup.html", uname=user, email=email,
                        error_name=error_name, error_password=error_password,
                        error_verify=error_verify, error_email=error_email)

class WelcomeHandler(Handler):
    def get(self):
        cookieUser = self.request.cookies.get('user')
        if is_userid_valid(cookieUser):
            user = User.get_by_id(int(cookieUser.split('|')[0]))
            self.render("welcome.html", uname=user.name)
        else :
            self.redirect('signup')

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', signupHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
