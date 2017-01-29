import os
import re
import random
import hashlib
import hmac
import time
import blogdb
from blogdb import User, Post, Comment
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'lebronjames'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    """Return val and hashed val using hmac"""
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    """Check if val and hased result match"""
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Basic bloghandler that provides HTML rendering, set up cookie and so on.
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

# Hash the users' passwords and check if matched in user authentication.
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


# Handler to render the front page.
class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

# Handler to render the blog page. Strong Consistency for comments query.
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blogdb.blog_key())
        post = db.get(key)
        comments = Comment.all().order('-created')
        comments = comments.filter("blog =", int(post_id))
        comments = comments.ancestor(blogdb.comment_key())

        # render 404 page if no such blog found.
        if not post:
            self.render('notfound.html')
            return
        self.render("permalink.html", post = post, comments = comments)

    # Post handles like function. If liked, update the post db model.
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blogdb.blog_key())
        post = db.get(key)
        comments = Comment.all().order('-created')
        comments = comments.filter("blog =", int(post_id))
        comments = comments.ancestor(blogdb.comment_key())
        if self.user:
            if self.user.name != post.author and self.user.name not in post.likedBy:
                post.likes += 1
                post.likedBy.append(self.user.name)
                post.put()
                error = ""
            else:
                error = "Invalid. You have liked this blog."
        self.render("permalink.html", post = post, error = error, comments = comments)

# Handler to post a new blog
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name
        likes = 0

        if subject and content:
            p = Post(parent = blogdb.blog_key(), subject = subject,
                     author = author, content = content, likes = likes)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)

# Handler to edit the post.
class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blogdb.blog_key())
            post = db.get(key)
            if post and self.user.name == post.author:
                self.render("edit.html", post = post)
            else:
                self.render("unauthorized.html")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blogdb.blog_key())
        post = db.get(key)
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "subject and content, please!"
            self.render("edit.html", subject=subject,
                        content=content, error=error)

# Handler to delete the post
class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blogdb.blog_key())
            post = db.get(key)
            if post and self.user.name == post.author:
                self.render("delete.html", post = post)
            else:
                self.render("unauthorized.html")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blogdb.blog_key())
        db.delete(key)
        self.redirect("/blog")


# Handler to post a comment
class CommentPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blogdb.blog_key())
            post = db.get(key)
            if post and self.user.name != post.author:
                self.render("newcomment.html", post = post)
            else:
                self.render("unauthorized.html")
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.name
        blog = int(post_id)

        if subject and content:
            c = Comment(parent = blogdb.comment_key(), subject = subject,
                     author = author, content = content, blog = blog)
            c.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("comment.html", subject=subject,
                        content=content, error=error)

# Handler to edit the comment. Use the same html file with Editpost
class EditComment(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Comment', int(post_id), parent=blogdb.comment_key())
            post = db.get(key)
            if post and self.user.name == post.author:
                self.render("edit.html", post = post)
            else:
                self.render("unauthorized.html")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Comment', int(post_id), parent=blogdb.comment_key())
        post = db.get(key)
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % str(post.blog))
        else:
            error = "subject and content, please!"
            self.render("edit.html", subject=subject,
                        content=content, error=error)

# Handler to delete the comment. Use the same html file with DeletePost
class DeleteComment(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Comment', int(post_id), parent=blogdb.comment_key())
            post = db.get(key)
            if post and self.user.name == post.author:
                self.render("delete.html", post = post)
            else:
                self.render("unauthorized.html")
        else:
            self.redirect("/login")

    def post(self, post_id):
        key = db.Key.from_path('Comment', int(post_id), parent=blogdb.comment_key())
        blog = db.get(key).blog
        db.delete(key)
        time.sleep(0.1)
        self.redirect("/blog/%s" % str(blog))


# Check if user signup is valid
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

# Handler to register for a new account
class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

# Handler to login the user
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

# Handler to logout the user
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

app = webapp2.WSGIApplication([('/', BlogFront),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/edit/([0-9]+)', EditPost),
                               ('/blog/delete/([0-9]+)', DeletePost),
                               ('/blog/comment/([0-9]+)', CommentPost),
                               ('/blog/comment/edit/([0-9]+)', EditComment),
                               ('/blog/comment/delete/([0-9]+)', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
