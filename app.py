# flaskblog/__init__.py
from flask import Flask
from flask_bcrypt import Bcrypt  # pip install Flask-Bcrypt https://pypi.org/project/Flask-Bcrypt/
from flask_sqlalchemy import SQLAlchemy  # pip install Flask-SQLAlchemy = https://pypi.org/project/Flask-SQLAlchemy/
from flask_login import LoginManager  # pip install Flask-Login = https://pypi.org/project/Flask-Login/
from flask_msearch import Search  # pip install flask-msearch = https://pypi.org/project/flask-msearch/
#flaskblog/routes.py
from flask import  render_template, redirect, url_for, request, flash,current_app,abort
from flask_login import login_user, login_required,logout_user,current_user
from forms import SignUpForm,LoginForm,PostForm
import os
import secrets
import logging
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:umer@localhost/Blog'
app.config['SECRET_KEY'] = 'c60a686689ce171579b6a6eb2b390d8b'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
search = Search()
search.init_app(app)

login_manager = LoginManager(app)

login_manager.login_view = "login"
login_manager.login_message_category = "info"
# flaskblog/models.py
from datetime import datetime
from flask_login import UserMixin
from sqlalchemy import event
from slugify import slugify

logging.basicConfig(filename='record.log', filemode='w' ,level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')
# logging.basicConfig(format = logFormatStr, filename = "global.log", level=logging.INFO,force=True ,format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile = db.Column(db.String(180), default="profile.jpg")

    def __repr__(self):
        return '<User %r>' % self.username


class Post(db.Model):
    __tablename__ = 'post'
    __searchable__ = ['title', 'body']
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), unique=True, nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    body = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(150), nullable=False, default='no-image.jpg')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    author = db.relationship('User', backref=db.backref('posts', lazy=True, passive_deletes=True))
    views = db.Column(db.Integer, default=0)
    comments = db.Column(db.Integer, default=0)
    feature = db.Column(db.String, default=1, nullable=False)
    date_pub = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return '<Post %r' % self.title

    @staticmethod
    def generate_slug(target, value, oldvalue, initiator):
        if value and (not target.slug or value != oldvalue):
            target.slug = slugify(value)


db.event.listen(Post.title, 'set', Post.generate_slug, retval=False)


class Comments(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=False, nullable=False)
    email = db.Column(db.String(200), unique=False, nullable=False)
    message = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id', ondelete='CASCADE'), nullable=False)
    post = db.relationship('Post', backref=db.backref('posts', lazy=True, passive_deletes=True))
    feature = db.Column(db.Boolean, default=False, nullable=False)
    date_pub = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return '<Post %r' % self.name

def save_photo(photo):
    rand_hex = secrets.token_hex(10)
    _, file_extention = os.path.splitext(photo.filename)
    file_name = rand_hex + file_extention
    file_path = os.path.join(current_app.root_path, 'static/images', file_name)
    photo.save(file_path)
    return file_name


@app.route('/')
def index():
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('post/index.html', posts=posts)


@app.route('/news/<string:slug>', methods=['POST', 'GET'])
def news(slug):
    post = Post.query.filter_by(slug=slug).first()
    comment = Comments.query.filter_by(post_id=post.id).filter_by(feature=True).all()
    post.views = post.views + 1
    db.session.commit()
    Thanks = ""
    if request.method == "POST":
        post_id = post.id
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        comment = Comments(name=name, email=email, message=message, post_id=post_id)
        db.session.add(comment)
        post.comments = post.comments + 1
        db.session.commit()
        flash('Your comment has been submited  submitted will be published after aproval of admin', 'success')
        return redirect(request.url)

    return render_template('post/news-details.html', post=post, comment=comment, Thanks=Thanks)


@app.route('/search')
def search():
    keyword = request.args.get('q')
    posts = Post.query.msearch(keyword, fields=['title'], limit=6)
    return render_template('post/search.html', posts=posts)


@app.route('/admin')
@login_required
def admin():
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('admin/home.html', posts=posts)


@app.route('/comments/', methods=['POST', 'GET'])
def comments():
    comments = Comments.query.order_by(Comments.id.desc()).all()
    return render_template('admin/comment.html', comments=comments)


@app.route('/check/<int:id>', methods=['POST', 'GET'])
@login_required
def check(id):
    comment = Comments.query.get_or_404(id)
    if (comment.feature == True):
        comment.feature = False
        db.session.commit()
    else:
        comment.feature = True
        db.session.commit()
        return redirect(url_for('comments'))
    return redirect(url_for('comments'))


@app.route('/addpost', methods=['POST', 'GET'])
@login_required
def addpost():
    form = PostForm(request.form)
    if request.method == "POST" and form.validate():
        photo = save_photo(request.files.get('photo'))
        post = Post(title=form.title.data, body=form.content.data, category=request.form.get('category'), image=photo,
                    author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been added ', 'success')
        return redirect(url_for('admin'))
    return render_template('admin/addpost.html', form=form)


@app.route('/update/<int:id>', methods=['POST', 'GET'])
@login_required
def update(id):
    form = PostForm(request.form)
    post = Post.query.get_or_404(id)
    form.title.data = post.title
    form.content.data = post.body
    if request.method == 'POST' and form.validate():
        if request.files.get('photo'):
            try:
                os.unlink(os.path.join(current_app.root_path, 'static/images/' + post.image))
                post.image = save_photo(request.files.get('photo'))
            except:
                post.image = save_photo(request.files.get('photo'))
        post.title = form.title.data
        post.body = form.content.data
        post.category = request.form.get('category')
        flash('Post has been updated', 'success')
        db.session.commit()
        return redirect(url_for('admin'))
    return render_template('admin/addpost.html', form=form, post=post)


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    post = Post.query.get_or_404(id)
    try:
        os.unlink(os.path.join(current_app.root_path, 'static/images/' + post.image))
        db.session.delete(post)
    except:
        db.session.delete(post)
    flash('Post has deleted ', 'success')
    db.session.commit()
    return redirect(url_for('admin'))


@app.route('/delcomment/<int:id>')
@login_required
def delcomment(id):
    comment = Comments.query.get_or_404(id)
    db.session.delete(comment)
    db.session.commit()
    flash('Comment has deleted ', 'success')
    return redirect(url_for('admin'))


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    form = SignUpForm(request.form)
    if request.method == 'POST' and form.validate():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user = User(name=form.name.data, username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Thanks for registering, you able to login now', 'success')
        return redirect(url_for('login'))
    return render_template('admin/signup.html', form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():  # username : admin pass: cairocoders
    if current_user.is_authenticated:
        next = request.args.get('next')
        return redirect(next or url_for('admin'))
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User.query.filter_by(username=form.username.data).first()
        if not user:
            flash('This user not exists', 'warning')
            return redirect(url_for('login'))
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            next = request.args.get('next')
            return redirect(next or url_for('admin'))
        flash('Invalid password', 'danger')
    return render_template('admin/login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('you are logout', 'success')
    return redirect(url_for('login'))
if __name__ == "__main__":
    import logging

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)

    logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(module)s %(funcName)s %(message)s',
                    handlers=[logging.FileHandler("my_log.log", mode='w'),
                              stream_handler])
    logFormatStr = '[%(asctime)s] p%(process)s {%(pathname)s:%(lineno)d} %(levelname)s - %(message)s'
    logging.basicConfig(format = logFormatStr, filename = "global.log" , filemode='w' , encoding='utf-8' , level=logging.DEBUG)
    formatter = logging.Formatter(logFormatStr,'%m-%d %H:%M:%S')
    fileHandler = logging.FileHandler("summary.log")
    fileHandler.setLevel(logging.DEBUG)
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setLevel(logging.DEBUG)
    streamHandler.setFormatter(formatter)
    app.logger.addHandler(fileHandler)
    app.logger.addHandler(streamHandler)
    app.logger.info("Logging is set up.")


    app.run(debug=True ,port=8948,use_reloader=False)