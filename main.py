from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from forms import RegisterForm, LoginForm, CommentForm
from functools import wraps
from sqlalchemy import ForeignKey

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    author = relationship("Users", back_populates="posts")
    comments = relationship("Comments", back_populates="post")


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="user")


class Comments(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    user = relationship("Users", back_populates="comments")
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    post = relationship("BlogPost", back_populates="comments")


@login_manager.user_loader
def load_user(user_id):
    if user_id:
        return Users.query.get(int(user_id))


# db.create_all()


def admin_only(f):
    @wraps(f)
    def wrapper_fun(*args, **kwargs):
        if current_user is None:
            abort(403, description="You don't have the access to see the requested resource.")
        if current_user.id == 1:
            return f(*args, **kwargs)
        else:
            abort(403, description="You don't have the access to see the requested resource.")

    return wrapper_fun


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    print(posts)
    if '_flashes' in session:
        session['_flashes'].clear()
    return render_template("index.html", all_posts=posts, is_logged_in=current_user.is_authenticated, user=current_user)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        user = Users.query.filter_by(email=request.form['email']).first()
        hashed_pwd = generate_password_hash(request.form['password'], method='pbkdf2:sha256', salt_length=8)
        if user:
            flash("You have already signed up with that email. log in instead? ")
            return redirect(url_for('login'))
        user = Users(name=request.form['name'], password=hashed_pwd, email=request.form['email'])
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect('/')
    return render_template("register.html", form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()

    if request.method == 'POST':
        user = Users.query.filter_by(email=request.form['email']).first()
        if user:
            if check_password_hash(user.password, request.form['password']):
                login_user(user)
                flash('Logged in successfully.')
                return redirect('/')
            else:
                flash("Please enter the correct password for the user!!")
        else:
            flash("The email does not exist!!")
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    comment_form = CommentForm()
    if request.method == 'POST':
        if current_user.is_authenticated:
            form = CommentForm()
            if form.validate_on_submit():
                new_comment = Comments(
                    text=form.comment.data,
                    user_id=current_user.id,
                    post_id=post_id
                )
                db.session.add(new_comment)
                db.session.commit()
        else:
            flash('Please login to comment.')
            return redirect(url_for('login'))

    requested_post = BlogPost.query.get(post_id)
    post_comments = requested_post.comments

    return render_template("post.html", post=requested_post, user=current_user, comment_form=comment_form,
                           is_logged_in=current_user.is_authenticated, post_comments=post_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
