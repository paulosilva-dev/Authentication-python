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

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

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

        user = self.request.get("username")
        pw = self.request.get("password")
        pw2 = self.request.get("verify")
        email = self.request.get("email")

        userValid = valid_username(user)
        pwValid = valid_password(pw)
        pwMatch = pw == pw2
        emaiValid = True
        if email:
            emaiValid = valid_email(email)
        # error messages
        error_name = 'Invalid Name'
        error_name = 'User name already taken'
        error_password = 'Invalid password'
        error_verify = "Passwords don't match"
        error_email = 'Invalid email'


        if userValid and pwValid and pwMatch and emaiValid:
            #set cookie
            self.redirect('welcome')
        else:
            self.render("signup.html", uname=user, email=email,
                        error_name=error_name, error_password=error_password,
                        error_verify=error_verify, error_email=error_email)

class WelcomeHandler(Handler):
    def get(self):
        self.render("welcome.html", uname="uname")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', signupHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
