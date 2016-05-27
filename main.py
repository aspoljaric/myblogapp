import webapp2
import os
import re
import jinja2
import random
import hashlib
import hmac
import time
from string import letters
from google.appengine.ext import db

jinja_env = jinja2.Environment(autoescape=True,
            loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__)
            ,'templates')))






#### Cookies
secret = 'Cfnjefnewjn@482i2u4929UD@*&YD@&*GD@'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
#### End Cookies






#### Helper Handler
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

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
#### End Helper Handler






#### Database Classes

#### Blog Class
class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    username = db.StringProperty(required = True)
    is_deleted = db.BooleanProperty(required = True, default = False)

    @classmethod
    def number_of_likes(cls, blog_id):
        numb_likes = Like.all().filter('blog_id =', blog_id).count()
        return numb_likes

    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')
        t = jinja_env.get_template("post.html")
        numb_likes = Blog.number_of_likes(self.key().id())
        return t.render(b = self, user = user, numb_likes = numb_likes)
#### End Blog Class

#### Comment Class
class Comment(db.Model):
    blog_id = db.IntegerProperty(required = True)
    comment = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    username = db.StringProperty(required = True)
    is_deleted = db.BooleanProperty(required = True, default = False)

    def render(self, user):
        self._render_text = self.comment.replace('\n', '<br>')
        t = jinja_env.get_template("comment.html")
        return t.render(c = self, user = user)
#### End Comment Class

### User Class
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def valid_pw(username, password, h):
    salt = h.split(',')[0]
    return h == make_password_hash(username.lower(), password, salt)

def make_password_hash(username, password, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username.lower() + password + salt).hexdigest()
    return '%s,%s' % (salt, h)

class User(db.Model):
    username = db.StringProperty(required = True)
    first_name = db.StringProperty(required = True)
    last_name = db.StringProperty(required = True)
    email = db.StringProperty()
    password_hash = db.StringProperty(required = True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, username):
        u = User.all().filter('username =', username.lower()).get()
        return u

    @classmethod
    def register(cls, username, first_name, last_name, password, email = None):
        password_hash = make_password_hash(username.lower(), password)
        return User(username = username.lower(),
                    first_name = first_name,
                    last_name = last_name,
                    password_hash = password_hash,
                    email = email)

    @classmethod
    def login(cls, username, password):
        u = cls.by_name(username.lower())
        if u and valid_pw(username.lower(), password, u.password_hash):
            return u
### End User Class

#### Like Class
class Like(db.Model):
    blog_id = db.IntegerProperty(required = True)
    username = db.StringProperty(required = True)

    @classmethod
    def by_username_by_blog_id(cls, username, blog_id):
        l = Like.all().filter('username =', username.lower()).filter('blog_id =', blog_id).get()
        return l
#### End Like Class

#### End Database Classes






#### Sign Up Validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)

NAME_RE = re.compile(r"^[a-zA-Z_-]")
def valid_name(name):
    return NAME_RE.match(name)
#### End Sign Up Validation






#### Process user sign up information
class SignUpHandler(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.first_name = self.request.get('first_name')
        self.last_name = self.request.get('last_name')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email,
                      first_name = self.first_name,
                      last_name = self.last_name,
                      error_username = '')

        if not valid_name(self.first_name):
            params['error_first_name'] = "That's not a valid first name."
            have_error = True

        if not valid_name(self.last_name):
            params['error_last_name'] = "That's not a valid last name."
            have_error = True

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
            self.render('signup.html', **params)
        else:
            user = User.by_name(self.username)

            if user:
                
                params['error_username'] = "That user already exists."
                self.render('signup.html', **params)
            else:
                user = User.register(self.username, self.first_name, self.last_name, self.password, self.email)
                user.put()
                self.redirect('/')
                self.login(user)
#### End Process user sign up information





#### Process user login and log out
class LoginHandler(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)

        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login.'
            self.render('login.html', error = msg)

class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect('/')
#### End Process user login and log out







#### Process operations on Blog Entries
class NewBlogHandler(Handler):
    def get(self):
        if self.user:
            self.render("newblog.html", is_new = True)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            b = Blog(subject = subject, 
                     content = content, 
                     username = self.user.username)
            b.put()
            self.redirect('/%s' % str(b.key().id()))
        else:
            error = "Please enter subject and content."
            params = dict(subject = subject,
                          content = content,
                          error = error,
                          is_new = True)
            self.render("newblog.html", **params)    


class BlogEntryPage(Handler):
    def get(self, blog_id):
        key = db.Key.from_path('Blog', int(blog_id))
        blog = db.get(key)

        if not blog:
            self.error(404)
            return

        comments = Comment.all().order('-created').filter('blog_id =', int(blog_id)).filter('is_deleted =', False)
        self.render("permalink.html", blog = blog, comments = comments)


class LikeBlogEntryPage(Handler):
    def get(self, blog_id):
        if self.user:
            key = db.Key.from_path('Blog', int(blog_id))
            blog = db.get(key)

            if not blog:
                self.error(404)
                return

            existing_like = Like.by_username_by_blog_id(self.user.username, int(blog_id))

            if not existing_like and (blog.username != self.user.username):
                new_like = Like(blog_id = int(blog_id), username = self.user.username)
                new_like.put()

            time.sleep(0.1)
            self.redirect('/%s' % str(blog.key().id()))

        else:
            self.redirect("/login")




class DeleteBlogHandler(Handler):
    def get(self, blog_id):
        if self.user:
            key = db.Key.from_path('Blog', int(blog_id))
            blog = db.get(key)

            if not blog:
                self.error(404)
                return

            blog.is_deleted = True
            blog.put()

            time.sleep(0.1)
            self.redirect('/')
        else:
            self.redirect("/login")


class EditBlogHandler(Handler):
    def get(self, blog_id):
        if self.user:
            key = db.Key.from_path('Blog', int(blog_id))
            blog = db.get(key)

            if not blog:
                self.error(404)
                return

            params = dict(subject = blog.subject,
                          content = blog.content,
                          is_new = False,
                          blog_id = blog_id)
            self.render("newblog.html", **params)

        else:
            self.redirect("/login")

    def post(self, blog_id):
        if not self.user:
            self.redirect('/')

        key = db.Key.from_path('Blog', int(blog_id))
        blog = db.get(key)

        if not blog:
            self.error(404)
            return

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            blog.subject = subject
            blog.content = content
            blog.put()
            self.redirect('/%s' % str(blog.key().id()))
        else:
            error = "Please enter subject and content."
            params = dict(subject = subject,
                          content = content,
                          error = error,
                          is_new = False,
                          blog_id = blog_id)
            self.render("newblog.html", **params)    
#### End Process operations on Blog Entries






#### Process operations on Comment Entries
class CommentHandler(Handler):
    def get(self, blog_id):
        if self.user:
            key = db.Key.from_path('Blog', int(blog_id))
            blog = db.get(key)

            if not blog:
                self.error(404)
                return

            self.render("newcomment.html", is_new = True)

        else:
            self.redirect("/login")
    def post(self, blog_id):
        if not self.user:
            self.redirect('/')

        comment = self.request.get('comment')

        key = db.Key.from_path('Blog', int(blog_id))
        blog = db.get(key)
        if not blog:
            self.error(404)
            return

        if comment:
            c = Comment(blog_id = blog.key().id(), 
                     comment = comment, 
                     username = self.user.username)
            c.put()

            time.sleep(0.1)
            self.redirect('/%s' % str(blog.key().id()))
        else:
            error = "Please enter a comment."
            params = dict(comment = comment,
                          error = error,
                          is_new = True)
            self.render("newcomment.html", **params)    


class DeleteCommentHandler(Handler):
    def get(self, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            if not comment:
                self.error(404)
                return

            comment.is_deleted = True
            comment.put()

            time.sleep(0.1)
            self.redirect('/%s' % str(comment.blog_id))
        else:
            self.redirect("/login")



class EditCommentHandler(Handler):
    def get(self, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            if not comment:
                self.error(404)
                return

            params = dict(comment = comment.comment,
                          is_new = False,
                          blog_id = comment.blog_id)
            self.render("newcomment.html", **params)

        else:
            self.redirect("/login")

    def post(self, comment_id):
        if not self.user:
            self.redirect('/')

        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        if not comment:
            self.error(404)
            return

        comment_form = self.request.get('comment')

        if comment_form:
            comment.comment = comment_form
            comment.put()

            time.sleep(0.1)
            self.redirect('/%s' % str(comment.blog_id))
        else:
            error = "Please enter a comment."
            params = dict(comment = comment_form,
                          error = error,
                          is_new = False,
                          blog_id = comment.blog_id)
            self.render("newcomment.html", **params)   
#### End Process operations on Blog Entries





#### Home page
class MainHandler(Handler):
    def get(self):
        blogs = Blog.all().filter('is_deleted =', False).order('-created')
        self.render('home.html', blogs = blogs)
#### End Home Page






app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/([0-9]+)', BlogEntryPage),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/signup', SignUpHandler),
    ('/newblog', NewBlogHandler),
    ('/like/([0-9]+)', LikeBlogEntryPage),
    ('/comment/([0-9]+)', CommentHandler),
    ('/deleteblog/([0-9]+)', DeleteBlogHandler),
    ('/deletecomment/([0-9]+)', DeleteCommentHandler),
    ('/editblog/([0-9]+)', EditBlogHandler),
    ('/editcomment/([0-9]+)', EditCommentHandler)
], debug=True)
