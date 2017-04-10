#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import webapp2
import jinja2
import random
import hashlib
import hmac
import re
import time

from google.appengine.ext import db
from string import letters

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'sars'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# make a safe value from the variable "val" and the secret word "secret"


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# check if a given passed value is valid


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# main class


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # set a cookie based on "name" and "val" passed
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        # add cookie to header of response page
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # check if a cookie is valid
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # set a cookie to login user
    def login_cookie(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # overwrite a login cookie, end the session
    def logout_cookie(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # check if user is logged in. GAE function
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# step1

# redirect path '/' to '/blog/'


class MainPage(BlogHandler):

    def get(self):
        self.redirect('/blog/')


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# post object


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True, default=0)
    liked_by = db.StringListProperty(default=[])
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        self._id = self.key().id()
        return render_str("post.html", p=self)


# create a new post to blog


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            init = 2
            self.render('newpost.html', init=init)
        else:
            init = 3
            self.redirect('/blog/signup')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name

        if subject and content and author:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, author=author)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content and author, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


class PostPage(BlogHandler):

    def get(self, post_id):
        # Key.from_path(*path, parent=None, namespace=None)
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if self.user:
            username = self.user.name
            init = 2
            self.render("permalink.html", p=post, init=init, username=username)
        else:
            init = 3
            self.redirect('/blog/login')


class BlogFront(BlogHandler):

    def get(self):
        posts = Post.all().order('-created')
        if self.user:
            username = self.user.name
            init = 2
            self.render('front.html', posts=posts,
                        init=init, username=username)
        else:
            init = 3
            self.render('front.html', posts=posts, init=init)


# step2

# make a salt to store in databese instead password


def make_salt(lenght=5):
    return ''.join(random.choice(letters) for x in xrange(lenght))

# make a hash to store in databese instead password


def make_password_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# check if password passed is valid


def valid_password(name, password, h):
    salt = h.split(',')[0]
    return h == make_password_hash(name, password, salt)

# create a user element in database


def users_key(group='default'):
    return db.Key.from_path('users', group)

# user object


class User(db.Model):
    name = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    posts_liked = db.StringListProperty(default=[])

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, password, email=None):
        password_hash = make_password_hash(name, password)
        return User(parent=users_key(), name=name,
                    password_hash=password_hash, email=email)

    @classmethod
    def login(cls, name, password):
        u = cls.by_name(name)
        if u and valid_password(name, password, u.password_hash):
            return u


# rule to check if username input in register is valid
USER_RE = re.compile(r"^^[a-zA-Z0-9_-]{3,20}$")


def valid_username_input(username):
    return username and USER_RE.match(username)

# rule to check if password input in register is valid
PASS_RE = re.compile(r"^.{3,20}$")


def valid_password_input(password):
    return password and PASS_RE.match(password)

# rule to check if email input in register is valid
EMAIL_RE = re.compile(r'^[\S]+@+[\S]+\.[\S]+$')


def valid_email_input(email):
    return not email or EMAIL_RE.match(email)


# render signup form and check if inputs are valid
class Signup(BlogHandler):

    def get(self):
        init = 3
        self.render("signup-form.html", init=init)

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        # verify username input
        if not valid_username_input(self.username):
            params['error_username'] = 'Not a valid username'
            have_error = True

        # verify password input
        if not valid_password_input(self.password):
            params['error_password'] = 'Not a valid password'
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = 'Yours password did not match'
            have_error = True

        # verify email input
        if not valid_email_input(self.email):
            params['error_email'] = 'Not a valid email'
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):
        # search user's name in database
        u = User.by_name(self.username)
        if u:
            msg = "That's user already exists"
            self.render('signup-form.html', error_username=msg)
        else:
            # create user object
            u = User.register(self.username, self.password, self.email)
            # save user object in datebase
            u.put()

            self.login_cookie(u)
            self.redirect('/blog/welcome')


class Login(BlogHandler):

    def get(self):
        init = 3
        self.render('login-form.html', init=init)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        # check if user is in database
        u = User.login(username, password)
        if u:
            self.login_cookie(u)
            self.redirect('/blog/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout_cookie()
        self.redirect('/blog')


class Welcome(BlogHandler):

    def get(self):
        if self.user:
            init = 2
            author = self.user.name
            author_posts = Post.all().filter('author =', author).order('-created')
            self.render('welcome.html', username=author,
                        init=init, author_posts=author_posts)
        else:
            init = 3
            self.redirect('/blog')


class Like(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            init = 2
            username = self.user.name
            if not post:
                self.error(404)
                return
            else:
                author = post.author
                current_user = self.user.name
                redirect = int(post_id)
                if author == current_user:
                    msg = "You can't like your own post"
                    self.render('permalink.html', p=post,
                                init=init, msg=msg, redirect=redirect, username=username)
                elif current_user in post.liked_by:
                    msg = "You've already liked"
                    self.render('permalink.html', p=post,
                                init=init, msg=msg, redirect=redirect, username=username)
                else:
                    post.likes += 1
                    post.liked_by.append(current_user)
                    post.put()
                    msg = 'Liked'
                    self.render("permalink.html", p=post,
                                init=init, msg=msg, redirect=redirect, username=username)


class Unlike(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            init = 2
            if not post:
                self.error(404)
                return
            else:
                current_user = self.user.name
                redirect = ''
                post.likes -= 1
                post.liked_by.remove(current_user)
                post.put()
                msg = 'Unliked'
                self.render("permalink.html", p=post,
                            init=init, msg=msg, redirect=redirect)


"""
class Tetse(BlogHandler):

    def get(self):
        x = db.Key.from_path('blogs', 'default')
        self.render('teste.html', x=x)
"""

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', Register),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/welcome', Welcome),
                               ('/blog/like/([0-9]+)', Like),
                               ('/blog/unlike/([0-9]+)', Unlike),
                               # ('/blog/teste', Tetse),
                               ],
                              debug=True)
