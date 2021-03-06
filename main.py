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


##GLOBAL FUNCTIONS
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

#functions for salting and hashing user password
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

#Users database parent and Posts database parent. Gets key from respective db
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

		#allows for sending "user" to the template. checks to see if user is signed in.
		params["user"] = self.user
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

	#get user with userid
	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	#get user by name
	@classmethod
	def by_name(cls, name):
		u = User.all().filter("name =", name).get()
		return u

	#hash password when registering
	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(), name = name, pw_hash = pw_hash, email = email)

	#check hashed password when logging in
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
	user = db.ReferenceProperty(User, required = True, collection_name = "posts")

	#renders line breaks correctly after posting
	def render(self):
		self._render_text = self.content.replace("\n", "<br>")
		return render_str("post.html", p=self)

#creates like database
class Likes(db.Model):
	post = db.ReferenceProperty(Post, required= True)
	user = db.ReferenceProperty(User, required = True)

	#get number of likes for a post by id
	@classmethod
	def post_likes(cls, post_id):
		l=Likes.all().filter("post =", post_id)
		return l.count()

	#get number of likes for a post and user id
	@classmethod
	def check_likes(cls, post_id, user_id):
		l=Likes.all().filter("post =", post_id).filter("user =", user_id)
		return l.count()

##creates comment database
class Comments(db.Model):
	post = db.ReferenceProperty(Post, required = True)
	user = db.ReferenceProperty(User, required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	text = db.TextProperty(required = True)

	#returns number of comments a post has
	@classmethod
	def comment_count(cls, post_id):
		c = Comments.all().filter("post =", post_id)
		return c.count()

	#returns all the comments for a specific post
	@classmethod
	def post_comments(cls, post_id):
		c = Comments.all().filter("post =", post_id).order("created")
		return c


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
			self.redirect("/")
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
		#gets key of the post
		key = db.Key.from_path("Post", int(post_id), parent = blog_key())
		post = db.get(key)

		#if post does not exist report error
		if not post:
			self.error(404)
			return

		#get likes and comments for each post searched by post key (id)
		likes = Likes.post_likes(post)
		comment_content = Comments.post_comments(post)
		comments_total = Comments.comment_count(post)

		#render page with content, likes, comments, and buttons to interact with
		self.render("permalink.html", post = post, likes = likes,
			comments_total = comments_total, comment_content = comment_content)


	def post(self, post_id):
		#gets required parameters
		key = db.Key.from_path("Post", int(post_id), parent = blog_key())
		post = db.get(key)
		user_id = User.by_name(self.user.name)
		likes = Likes.post_likes(post)
		prev_like = Likes.check_likes(post, user_id)
		comment_content = Comments.post_comments(post)
		comments_total = Comments.comment_count(post)

		#checks if user is logged in
		if self.user:
			#checks if the user clicked on like
			if self.request.get("likes"):
				#checks and makes sure user is not the author of the post
				if post.user.key().id() != User.by_name(self.user.name).key().id():
					#checks to make sure user has not liked the post previuosly
					if prev_like == 0:
						#likes the post. increments likes by 1
						l = Likes(post = post, user = User.by_name(self.user.name))
						l.put()
						time.sleep(0.1)
						self.redirect("/%s" % str(post.key().id()))#could use % post_id

					#if post already liked throws an error
					else:
						error = "You can only like a post once"
						self.render("permalink.html", post = post, likes = likes, error = error,
							comment_content = comment_content, comments_total = comments_total)

				#if user is the author of post throws an error
				else:
					error = "You can't like your own post"
					self.render("permalink.html", post = post, likes = likes, error = error,
						comments_total = comments_total, comment_content = comment_content)

			#checks to see if user wanted to add a comment
			if self.request.get("add_comment"):
				#if the comment is not empty comment is posted and stored in database.
				comment_text = self.request.get("comment_text")
				if comment_text:
					c = Comments(post = post, user = User.by_name(self.user.name), text = comment_text)
					c.put()
					time.sleep(0.2)
					self.redirect("/%s" % str(post.key().id()))#could use % post_id

				#if there is no content in the comment field throws an error.
				else:
					comment_error = "You need to enter a comment before you can post it"
					self.render("permalink.html", post = post, likes=likes,  comment_error= comment_error,
						comment_content = comment_content, comments_total = comments_total)

			#checks to see if user clicked edit post
			if self.request.get("edit"):
				#checks to see if user is the author of the post and if they are lets them edit it
				if post.user.key().id() == User.by_name(self.user.name).key().id():
					self.redirect("/edit/%s" % str(post.key().id()))#could use % post_id

				#if user is not the author throws an error
				else:
					error = "This post is not yours. You cannot edit it."
					self.render("permalink.html", post = post, likes = likes, error = error,
						comments_total = comments_total, comment_content = comment_content)

			#checks to see if user clicked delete
			if self.request.get("delete"):
				#checks to see if user is the author of psot and if they are lets them delete it
				if post.user.key().id() == User.by_name(self.user.name).key().id():
					db.delete(key)
					time.sleep(0.1)
					self.redirect("/")

				#if the user is not the author throws an error
				else:
					error = "You can only delete your own posts"
					self.render("permalink.html", likes = likes, post = post, error = error,
						comment_content = comment_content, comments_total = comments_total)

		#if the user is not signed in redirected to the login page
		else:
			self.redirect("/login")


#new post handler renders new post page and checks to make sure content and subject are provided before commiting to datastore
class NewPost(Handler):
	def get(self):

		if self.user:
			self.render("newpost.html")
		else:
			self.redirect("/login")

	def post(self):
		if self.user:
			subject = self.request.get("subject")
			content = self.request.get("content")
			user_id = User.by_name(self.user.name)

			if subject and content:
				p = Post(parent = blog_key(), subject = subject, content = content, user = user_id)
				p.put()
				self.redirect("/%s" % str(p.key().id()))

			else:
				error = "Subject and content are both required!"
				self.render("newpost.html", subject = subject, content = content, error = error)

		else:
			error = "You need to be logged in to perform that action"
			self.render("newpost.html", error = error)

#handler for editing a post
class EditPost(Handler):

	def get(self, post_id):
		#gets the post key
		key = db.Key.from_path("Post", int(post_id), parent = blog_key())
		post = db.get(key)

		#check to make sure user is logged in before rendering edit page and that they are the author of the post.
		if self.user:
			if post.user.key().id() == User.by_name(self.user.name).key().id():

				#renders edit page with post subject and content filled in with data from the datastore
				self.render("edit.html", subject = post.subject, content = post.content)

		else:
			error = "You need to be logged in to do that."
			self.render("edit.html", error = error)


	def post(self, post_id):
		#gets the post key
		key = db.Key.from_path("Post", int(post_id), parent = blog_key())
		post = db.get(key)

		#if user clicks update get the subject and the content from the form
		if self.request.get("update"):
			subject = self.request.get("subject")
			content = self.request.get("content")

			#checks that the logged in user is the user of the post.
			if post.user.key().id() == User.by_name(self.user.name).key().id():


				#if user provides subject and content update the post and save it in the datastore
				if subject and content:

					post.subject = subject
					post.content = content
					post.put()
					time.sleep(0.1)
					self.redirect("/%s" % str(post.key().id()))#could use % post_id

				#if user does not provide both a subject and content throw an error
				else:
					error = "Subject and content are both needed"
					self.render("edit.html", subject = subject, content = content, error = error)

			else:
				error = "You can't edit other user's posts"
				self.render("edit.html", subject = subject, content = content, error = error)

		#if user clicks cancel redirect to the permalink post page
		elif self.request.get("cancel"):
			self.redirect("/%s" % str(post.key().id()))#could use % post_id

#handler for posting comments
class PostComment(Handler):
	def get(self, post_id, comment_id):

		#gets post and comment from post id and comment id
		post = Post.get_by_id(int(post_id), parent=blog_key())
		comment = Comments.get_by_id(int(comment_id))

		#renders the comment edit page if the user is signed in
		if self.user:

			self.render("comment.html", comment_text = comment.text)

		else:
			error = "You need to be logged in to post a comment"
			self.render("comment.html", error = error)

	def post(self, post_id, comment_id):

		#gets post key and comment id

		key = db.Key.from_path("Post", int(post_id), parent = blog_key())
		post = db.get(key)
		comment = Comments.get_by_id(int(comment_id))

		#checks to make sure user is logged in before posting a comment
		if self.user:

			#if user clicks update comment and there is text in the textbox update the comment datastore with the new input
			if self.request.get("update_comment"):


				if self.request.get("comment_text"):

					comment.text = self.request.get("comment_text")
					comment.put()
					time.sleep(0.1)
					self.redirect("/%s" % str(post.key().id()))

				#if the comment has no content throw an error
				else:
					error = "Comment needs to have content"
					self.render("comment.html", error = error)

			#if user clicks cancel to edit comment redirect to permalink post page
			elif self.request.get("cancel_comment"):
				self.redirect("/%s" % str(post.key().id()))

		else:
			error = "You need to be logged in to post a comment"
			self.render("comment.html", error = error)

#handler for deleting comment
class DeleteComment(Handler):
	def get(self, post_id, comment_id):

		#get the comment by comment id
		comment = Comments.get_by_id(int(comment_id))

		#make sure user owns this comment before deleting
		if comment.user.name == self.user.name:

			#delete the comment and redirect to permalink post page
			if comment:
				db.delete(comment)
				time.sleep(0.1)
				self.redirect("/%s" % str(post_id))

		else:
			self.write("You can't delete a comment that you didn't post.")


app = webapp2.WSGIApplication([('/', MainPage),
							   ("/newpost", NewPost),
							   ("/([0-9]+)", PostPage),
							   ("/signup", Register),
							   ("/login", Login),
							   ("/logout", Logout),
							   ("/welcome", Welcome),
							   ("/edit/([0-9]+)", EditPost),
							   ("/([0-9]+)/comment/([0-9]+)", PostComment),
							   ("/([0-9]+)/deletecomment/([0-9]+)", DeleteComment)], debug=True)
