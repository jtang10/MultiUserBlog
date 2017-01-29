import blog
from google.appengine.ext import db

# Set up parent key for user model. Optional
def users_key(group='default'):
    return db.Key.from_path('users', group)

# SQL model for user information. password is hased before insertion.
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = blog.make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and blog.valid_pw(name, pw, u.pw_hash):
            return u

# Set up the parent key for blog model. Optional
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# SQL model for blog post.
class Post(db.Model):
    subject = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(required=True)
    likedBy = db.StringListProperty()

    # dedicated rendering for blog post. Can be used in both front page and
    # blog page.
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return blog.render_str("post.html", p=self)

# Set up the parent key for comment. Used fro strong consistency.
def comment_key(name='default'):
    return db.Key.from_path('comment', name)

# SQL model for comment.
class Comment(db.Model):
    subject = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    content = db.TextProperty(required=True)
    blog = db.IntegerProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return blog.render_str("comment.html", c=self)
