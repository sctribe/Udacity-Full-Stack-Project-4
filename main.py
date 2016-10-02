import os
import webapp2
import jinja2
import re
import random
import hmac
import hashlib
from string import letters
import time

from google.appengine.ext import db

#create environment for template
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

#secret used in hmac password hash
secret = "GnO>uHlmri[g2}<|Rl<6fc{SftpZkmN0"

#functions for checking and presenting hashed password in a cookie
def make_secure_val(val):
	return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split("|")[0]
	if secure_val == make_secure_val(val):
		return val

#function to render template with passed through parameters
def render_str(template, **params):
		#params["user"] = self.user
		t = jinja_env.get_template(template)
		return t.render(params)

#functions for hashing user password
def make_salt(length = 5):
	return "".join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s,%s" % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(",")[0]
	return h == make_pw_hash(name, password, salt)

#Users parent and Posts Parent
def users_key(group = "default"):
	return db.Key.from_path("users", group)

def blog_key(name = "default"):
	return db.Key.from_path("blogs", name)

#check validity of user entered username, password, and email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

#Main handler class. Contains useful functions
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

#Not needed since it is a global function
	def render_str(self, template, **params):
		#params["user"] = self.user
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

#Sets a cookie for the user id
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header("Set-Cookie", "%s=%s; Path=/" % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

#function that sets cookie when user logs in
	def login(self, user):
		self.set_secure_cookie("user_id", str(user.key().id()))

#function that deletes cookie when user logs out
	def logout(self):
		self.response.headers.add_header("Set-Cookie", "user_id=; Path=/")

#AppEngine function that runs on each process
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie("user_id")
		self.user = uid and User.by_id(int(uid))

#creates user database
class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

#class functions that can be run on class User instead of an instance of the class
	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter("name =", name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(), name = name, pw_hash = pw_hash, email = email)

	@classmethod
	def login(cls, name, pw):
		u=cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

#creates post database
class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace("\n", "<br>")
		return render_str("post.html", p=self)

#register page handler
class Signup(Handler):
	def get(self):
		self.render("signup.html")

#reads the user entered information on the register page and checks if its valid
	def post(self):
		have_error = False
		self.username = self.request.get("username")
		self.password = self.request.get("password")
		self.verify = self.request.get("verify")
		self.email = self.request.get("email")

		params = dict(username = self.username, email = self.email)

		if not valid_username(self.username):
			params["error_username"] = "Thats not a valid username."
			have_error = True

		if not valid_password(self.password):
			params["error_password"] = "This is not a valid password."
			have_error = True
		elif self.password != self.verify:
			params["error_verify"] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):
			params["error_email"] = "Thats not a valid email."
			have_error = True

		if have_error:
			self.render("signup.html", **params)
		else:
			self.done()

#not needed. overwritten in Register class
	def done(self, *a, **kw):
		raise NotImplementedError

#class that commits user to datastore if all entry data is valid and the username is not already registered.
class Register(Signup):
	def done(self):
		#checks to see if user already exists
		u = User.by_name(self.username)
		if u:
			msg = "That user already exists."
			self.render("signup.html", error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()

			self.login(u)
			self.redirect("/welcome")

#class that allows user to login. Checks that username and password hash match datastore
class Login(Handler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")

		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect("/welcome")
		else:
			msg = "Invalid Login"
			self.render("login.html", error = msg)

#deletes user cookie to logout user
class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect("/")

#welcome page handler redirects to welcome page when login or signup is successful
class Welcome(Handler):
	def get(self):
		if self.user:
			self.render("welcome.html", username = self.user.name)
		else:
			self.redirect("/signup")

#front page of blog handler. Shows all posts ordered by the order they were created
class MainPage(Handler):
	def get(self):
		posts = Post.all().order("-created") #posts = db.GqlQuery("select * from Post order by created desc")
		self.render("main.html", posts = posts)

#permalink page of post after successfully submitted from new post page
class PostPage(Handler):
	def get(self, post_id):
		key = db.Key.from_path("Post", int(post_id), parent = blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return


		self.render("permalink.html", post = post)

#new post handler renders new post page and checks to make sure content and subject are provided before commiting to datastore
class NewPost(Handler):
	def get(self):
		self.render("newpost.html")

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			p = Post(parent = blog_key(), subject = subject, content = content)
			p.put()
			self.redirect("/%s" % str(p.key().id()))

		else:
			error = "Subject and content are both required!"
			self.render("newpost.html", subject = subject, content = content, error = error)

app = webapp2.WSGIApplication([('/', MainPage),
							   ("/newpost", NewPost),
							   ("/([0-9]+)", PostPage),
							   ("/signup", Register),
							   ("/login", Login),
							   ("/logout", Logout),
							   ("/welcome", Welcome)], debug=True)
