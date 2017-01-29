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


class BlogHandler(webapp2.RequestHandler):
    """ Basic handler for this blog website.

    Key functions:
    render -- render the HTML page.
    login -- set cookie for user login.
    logout -- reset the cookie.
    intialized: initialize the page and get user info if logged in.
    """
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


class BlogFront(BlogHandler):
    """Handler for root of website."""
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)


class PostPage(BlogHandler):
    """Display individual blogs

    GET displays the blogs and related comments, 404 if no such blog.
    POST process the likes only. Can only be likes once by anyone but the
         author of this blog.
    """
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


class NewPost(BlogHandler):
    """Allow registered user to create new blog

    GET renders the newpost page and redirect to login if no user.
    POST initialize likes to 0 and store the blog to db.
    """
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


class EditPost(BlogHandler):
    """Allow author to edit his/her own blogs.

    GET displays the blog. If not logged in, ask to login. Will not render
        the page if not authorized.
    POST saves the modified blog back to db.
    """
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
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blogdb.blog_key())
            post = db.get(key)
            if post and self.user.name == post.author:
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
            else:
                self.render("unauthorized.html")
        else:
            self.redirect("/login")


class DeletePost(BlogHandler):
    """Allow author to delete his/her own blogs.

    GET displays the blog. If not logged in, ask to login. Will not render
        the page if not authorized.
    POST deletes the blog from db.
    """
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
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blogdb.blog_key())
            if post and self.user.name == post.author:
                db.delete(key)
                self.redirect("/blog")
            else:
                self.render("unauthorized.html")
        else:
            self.redirect("/login")


class CommentPost(BlogHandler):
    """Allow anyone but the author of this blog to comment.

    GET displays the newcomment.html. If not logged in, ask to login.
        Will not render the page if not authorized.
    POST stores the comment in the db.
    """
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


class EditComment(BlogHandler):
    """Allow author of comments to edit them.

    GET displays the comment. If not logged in, ask to login.
        Will not render the page if not authorized.
    POST stores the modified comment in the db.
    """
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Comment', int(post_id), parent=blogdb.comment_key())
            comment = db.get(key)
            if comment and self.user.name == comment.author:
                # still pass the comment into edit.html as post to reuse html.
                self.render("edit.html", post = comment)
            else:
                self.render("unauthorized.html")
        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Comment', int(post_id), parent=blogdb.comment_key())
            comment = db.get(key)
            if comment and self.user.name == comment.author:
                subject = self.request.get('subject')
                content = self.request.get('content')

                if subject and content:
                    comment.subject = subject
                    comment.content = content
                    comment.put()
                    self.redirect('/blog/%s' % str(comment.blog))
                else:
                    error = "subject and content, please!"
                    self.render("edit.html", subject=subject,
                                content=content, error=error)
            else:
                self.render("unauthorized.html")
        else:
            self.redirect("/login")


class DeleteComment(BlogHandler):
    """Allow author of the comments to delete them.

    GET displays the newcomment.html. If not logged in, ask to login.
        Will not render the page if not authorized.
    POST delete the comment from db.
    """
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Comment', int(post_id), parent=blogdb.comment_key())
            comment = db.get(key)
            if comment and self.user.name == comment.author:
                # still pass the comment into edit.html as post to reuse html.
                self.render("delete.html", post = comment)
            else:
                self.render("unauthorized.html")
        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Comment', int(post_id), parent=blogdb.comment_key())
            comment = db.get(key)
            if comment and self.user.name == comment.author:
                blog = comment.blog
                db.delete(key)
                self.redirect("/blog/%s" % str(blog))
            else:
                self.render("unauthorized.html")
        else:
            self.redirect("/login")


# Check if user signup is valid


class Signup(BlogHandler):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

    def valid_username(self, username):
        return username and Signup.USER_RE.match(username)

    def valid_password(self, password):
        return password and Signup.PASS_RE.match(password)

    def valid_email(self, email):
        return not email or Signup.EMAIL_RE.match(email)

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

        if not self.valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not self.valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not self.valid_email(self.email):
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
