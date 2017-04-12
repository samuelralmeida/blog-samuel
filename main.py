#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import webapp2
import jinja2
import random
import hashlib
import hmac
import re
from datetime import datetime

from google.appengine.ext import db
from string import letters

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# rewrite secret word
secret = 'sras'


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

# redirect path '/' to '/blog/'


class MainPage(BlogHandler):

    def get(self):
        self.redirect('/blog/')


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True, default=0)
    num_comments = db.IntegerProperty(required=True, default=0)
    liked_by = db.StringListProperty(default=[])
    created = db.DateTimeProperty(auto_now_add=True)
    # Can't use auto_now to last_modified because
    # when some likes or comment was count the date changed too
    last_modified = db.DateTimeProperty(required=False)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        self._id = self.key().id()
        return render_str("post.html", p=self)


# create a new post to blog


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            # variable logged is used by base.html to define page header
            self.render('newpost.html', logged=True)
        else:
            self.redirect('/blog/login')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name
        last_modified = datetime.now()

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                     content=content, author=author, last_modified=last_modified)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Sorry, but you must fill subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error, logged=True)


class PostPage(BlogHandler):

    def get(self, post_id):
        # Key.from_path(*path, parent=None, namespace=None)
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments_maked = Comment.all().filter(
            'post_commented = ', key).order('-created_comment')

        if not post:
            self.error(404)
            return

        if self.user:
            self.render("permalink.html", p=post,
                        comments_maked=comments_maked, logged=True)
        else:
            self.redirect('/blog/login')


class BlogFront(BlogHandler):

    def get(self):
        posts = Post.all().order('-created')
        if self.user:
            self.render('front.html', posts=posts, logged=True)
        else:
            self.render('front.html', posts=posts)


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
        self.render("signup-form.html")

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
        self.render('login-form.html')

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
            author = self.user.name
            author_posts = Post.all().filter('author =', author).order('-created')
            self.render('welcome.html', username=author,
                        logged=True, author_posts=author_posts)
        else:
            self.redirect('/blog')


class Like(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
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
                                logged=True, msg=msg, redirect=redirect, username=username)
                elif current_user in post.liked_by:
                    msg = "You've already liked"
                    self.render('permalink.html', p=post,
                                logged=True, msg=msg, redirect=redirect, username=username)
                else:
                    post.likes += 1
                    post.liked_by.append(current_user)
                    post.put()
                    msg = 'Liked'
                    self.render("permalink.html", p=post,
                                logged=True, msg=msg, redirect=redirect, username=username)


class Unlike(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            else:
                current_user = self.user.name
                if current_user in post.liked_by:
                    redirect = ''
                    post.likes -= 1
                    post.liked_by.remove(current_user)
                    post.put()
                    msg = 'Unliked'
                    self.render("permalink.html", p=post,
                                logged=True, msg=msg, redirect=redirect, username=current_user)
                else:
                    redirect = int(post_id)
                    msg = "You can't unlike if you haven't liked yet"
                    self.render("permalink.html", p=post,
                                logged=True, msg=msg, redirect=redirect, username=current_user)


class DeletePost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            else:
                current_user = self.user.name
                author = post.author
                if current_user == author:
                    # delete comments maked in post
                    db.delete(Comment.all(keys_only=True).filter(
                        'post_commented = ', key))
                    post.delete()
                    msg = "This post was deleted"
                    redirect = 'welcome'
                    self.render("permalink.html", p=post, logged=True,
                                msg=msg, redirect=redirect, username=current_user)
                else:
                    msg = "You can't delete a post by another user"
                    redirect = 'welcome'
                    self.render("permalink.html", p=post, logged=True,
                                msg=msg, redirect=redirect, username=current_user)


class EditPost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            current_user = self.user.name
            if post.author == current_user:
                subject = post.subject
                content = post.content
                self.render('editpost.html', subject=subject,
                            content=content, logged=True)
            else:
                msg = "You can't edit post by another user"
                redirect = 'welcome'
                self.render('permalink.html', p=post, logged=True,
                            msg=msg, redirect=redirect, username=current_user)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog/login')
        else:
            subject = self.request.get('subject')
            content = self.request.get('content')
            if subject and content:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                if not post:
                    self.error(404)
                    return
                current_user = self.user.name
                if post.author == current_user:
                    post.content = content
                    post.subject = subject
                    post.last_modified = datetime.now()
                    post.put()
                    self.redirect('/blog/%s' % str(post.key().id()))
                else:
                    msg = "You can't edit post by another user"
                    redirect = 'welcome'
                    self.render('permalink.html', p=post, logged=True,
                                msg=msg, redirect=redirect, username=current_user)
            else:
                error = "Sorry, but you must fill subject and content, please!"
                self.render("editpost.html", subject=subject,
                            content=content, error=error, logged=True)


class Comment(db.Model):
    content_comment = db.StringProperty(required=True)
    author_comment = db.StringProperty(required=True)
    created_comment = db.DateTimeProperty(auto_now_add=True)
    post_commented = db.ReferenceProperty(Post, collection_name='comments')

    def render(self):
        self._render_text = self.content_comment.replace('\n', '<br>')
        self._id = self.key().id()
        return render_str("comment.html", c=self)


class CommentPost(BlogHandler):

    def get(self, post_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            self.render("newcomment.html", p=post, logged=True)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')
        else:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not post:
                self.error(404)
                return
            else:
                comment = self.request.get('comment')
                if comment:
                    username = self.user.name
                    c = Comment(content_comment=comment, author_comment=username,
                                post_commented=key, parent=blog_key())
                    c.put()
                    post.num_comments += 1
                    post.put()
                    self.redirect('/blog/%s' % str(post_id))
                else:
                    error = 'Please, enter a comment'
                    self.render('newcomment.html', logged=True,
                                error=error, p=post)


class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            key_post = key = db.Key.from_path(
                'Post', int(post_id), parent=blog_key())
            post = db.get(key_post)
            key_comment = db.Key.from_path(
                'Comment', int(comment_id), parent=blog_key())
            comment = db.get(key_comment)
            if not post:
                self.error(404)
                return
            else:
                current_user = self.user.name
                author = comment.author_comment
                if current_user == author:
                    post.num_comments -= 1
                    post.put()
                    comment.delete()
                    msg = "This comment was deleted"
                    redirect = post_id
                    self.render("permalink.html", p=post, logged=True,
                                msg=msg, redirect=redirect, username=current_user)
                else:
                    msg = "You can't delete a comment by another user"
                    redirect = post_id
                    self.render("permalink.html", p=post, logged=True,
                                msg=msg, redirect=redirect, username=current_user)


class EditComment(BlogHandler):

    def get(self, post_id, comment_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            key_post = db.Key.from_path(
                'Post', int(post_id), parent=blog_key())
            post = db.get(key_post)
            key_comment = db.Key.from_path(
                'Comment', int(comment_id), parent=blog_key())
            comment = db.get(key_comment)
            if not post:
                self.error(404)
                return
            else:
                current_user = self.user.name
                author = comment.author_comment
                if current_user == author:
                    content_comment = comment.content_comment
                    self.render('editcomment.html', p=post,
                                logged=True, comment=content_comment)
                else:
                    msg = "You can't edit comment by another user"
                    redirect = post_id
                    self.render('permalink.html', p=post, logged=True,
                                msg=msg, redirect=redirect, username=current_user)

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect('/blog/login')
        else:
            content_comment = self.request.get('comment')
            if content_comment:
                key_post = db.Key.from_path(
                    'Post', int(post_id), parent=blog_key())
                post = db.get(key_post)
                key_comment = db.Key.from_path(
                    'Comment', int(comment_id), parent=blog_key())
                comment = db.get(key_comment)
                if not comment:
                    self.error(404)
                    return
                current_user = self.user.name
                if current_user == comment.author_comment:
                    comment.content_comment = content_comment
                    comment.put()
                    self.redirect('/blog/%s' % str(post.key().id()))
                else:
                    msg = "You can't edit post to another user"
                    redirect = post_id
                    self.render('permalink.html', p=post, logged=True,
                                msg=msg, redirect=redirect, username=current_user)
            else:
                error = "Sorry, but you must fill subject and content, please!"
                self.render("editpost.html",
                            comment=content_comment, error=error, logged=True)


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
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/comment/([0-9]+)', CommentPost),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                EditComment),
                               ],
                              debug=True)
