from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy 
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_wtf import FlaskForm
import os
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, InputRequired, Length, ValidationError
import requests
from flask_bcrypt import bcrypt
import bcrypt

class Config():
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')
    SECRET_KEY = os.environ.get('SECRET_KEY')

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10000), nullable = False, unique = True)
    password = db.Column(db.String(10000), nullable = False, unique = True)

class RegisterForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(min = 1, max = 10000)], render_kw = {'placeholder':'Username'})
    password = PasswordField(validators = [InputRequired(), Length(min = 1, max = 10000)], render_kw = {'placeholder':'Password'})
    submit = SubmitField('Register')   

class LoginForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length(min = 1, max = 10000)], render_kw = {'placeholder':'Username'})
    password = PasswordField(validators = [InputRequired(), Length(min = 1, max = 10000)], render_kw = {'placeholder':'Password'})
    submit = SubmitField('Login')

class ReviewForm(FlaskForm):
    author = StringField('Reviewer Name', validators=[DataRequired()])
    title = StringField('Review Title', validators=[DataRequired()])
    body = StringField('Review', validators=[DataRequired()])
    submit = SubmitField('Submit')

class EditReviewForm(FlaskForm):
    review_id = StringField('Review ID', validators=[DataRequired()])
    author = StringField('Reviewer Name', validators=[DataRequired()])
    title = StringField('Review Title', validators=[DataRequired()])
    body = StringField('Review', validators=[DataRequired()])
    submit = SubmitField('Submit')

class DeleteReviewForm(FlaskForm):
    review_id = StringField('Review ID', validators=[DataRequired()])
    submit = SubmitField('Submit')

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String)
    title = db.Column(db.String)
    body = db.Column(db.String)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/reviews')
def reviews():
    all_reviews = Review.query.all()
    return render_template('reviews.html', reviews=all_reviews)    

@app.route('/games')
def games():
    key = '48464d4b2c1544008092d9722a077ee8'
    page_num = 1
    url = f'https://api.rawg.io/api/games?key={key}&page={page_num}'
    # https://api.rawg.io/api/games?key=48464d4b2c1544008092d9722a077ee8&page=1
    response = requests.get(url)
    data = response.json()
    game_dicts = []
    for index, game in enumerate(data['results']):
        game_dict = {
            'image' : data['results'][index]['background_image'],
            'title' : data['results'][index]['name'],
            'meta_score' : data['results'][index]['metacritic'],
            'genre' : data['results'][index]['genres'][0]['name'],
            'esrb' : data['results'][index]['esrb_rating']['name'],
            'platform' : data['results'][index]['platforms'][0]['platform']['name']
        }
        game_dicts.append(game_dict)
    return render_template('games.html', game_dicts = game_dicts)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user:
            if bcrypt.checkpw(form.password.data.encode("utf-8"), user.password.encode("utf-8")):
                login_user(user)
                return redirect(url_for('index'))
    return render_template('login.html', form = form)

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=form.username.data, password=hashed_password.decode("utf-8"))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form = form)

@app.route('/submit_review', methods=['GET','POST'])
@login_required
def submit_review():
    form = ReviewForm()
    if request.method == 'POST' and form.validate_on_submit():
        author = form.author.data
        title = form.title.data
        body = form.body.data
        new_review = Review(author=author, title=title, body=body)
        db.session.add(new_review)
        db.session.commit()
        return redirect(url_for('reviews'))
    return render_template('submit_review.html', form = form)

@app.route('/edit_review', methods=['GET','POST'])
@login_required
def edit_review():
    form = EditReviewForm()
    if request.method == 'POST' and form.validate_on_submit():
        review_id = form.review_id.data
        author = form.author.data
        title = form.title.data
        body = form.body.data
        updated_review = Review.query.get(review_id) 
        updated_review.author = author
        updated_review.title = title
        updated_review.body = body
        db.session.commit()
        return redirect(url_for('reviews'))
    return render_template('edit_review.html', form = form)

@app.route('/delete_review', methods=['GET','POST'])
@login_required
def delete_review():
    form = DeleteReviewForm()
    if request.method == 'POST' and form.validate_on_submit():
        review_id = form.review_id.data
        deleted_review = Review.query.get(review_id)
        db.session.delete(deleted_review)
        db.session.commit()
        return redirect(url_for('reviews'))
    return render_template('delete_review.html', form = form)
