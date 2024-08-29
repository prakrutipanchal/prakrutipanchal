from flask import Flask, request, flash, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField,PasswordField,TextAreaField 
from wtforms.validators import DataRequired, EqualTo, Length
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from sqlalchemy import Text

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root_2005@localhost/users'
app.config['SECRET_KEY'] = 'awer62879304wegdfds'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
	return Register.query.get(user_id)

# flask db init                
# flask db migrate -m "Adjust bio column length"
# flask db upgrade

class Register(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(30), unique=True, nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    issue_time = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship('Posts', backref='poster')
    
class Posts(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(30), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    issue_time = db.Column(db.DateTime, default=datetime. utcnow)
    poster_id = db.Column(db.Integer, db.ForeignKey('register.id'))
    
	
# class User(db.Model):
# 	id = db.Column(db.Integer,primary_key=True, autoincrement=True)
# 	name = db.Column(db.String(25), nullable=False, unique=True)
# 	post = db.relationship('Post', back_populates='user', uselist=False)

# class Post(db.Model):
# 	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
# 	title = db.Column(db.String(100), nullable=False)
# 	content = db.Column(db.Text, nullable=False)
# 	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
# 	user = db.relationship('User', back_populates='post')

with app.app_context():
	db.create_all()

class SearchForm(FlaskForm):
	searched = StringField('Search', validators = [DataRequired()])
	submit = SubmitField('Submit')


class UserForm(FlaskForm):
	email = StringField('Email', validators = [DataRequired()])
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField("password", validators = [DataRequired(), EqualTo('confirm_password')])
	confirm_password = PasswordField("confirm_password", validators = [DataRequired()])
	submit = SubmitField('Submit')

class UserForm2(FlaskForm):
	email = StringField('Email', validators = [DataRequired()])
	password = PasswordField("password", validators = [DataRequired()])
	submit = SubmitField('Submit')

class PostForm(FlaskForm):
	title = StringField('Title', validators = [DataRequired()])
	content = TextAreaField("Content", validators = [DataRequired()])
	submit = SubmitField('Submit')

class UserForm3(FlaskForm):
	email = StringField('Email', validators = [DataRequired()])
	username = StringField('Username', validators=[DataRequired()])
	password_hash = PasswordField("password", validators = [DataRequired()])
	submit = SubmitField('Submit')

	def set_password(self,password):
		self.password_hash = generate_password_hash(password)

	def get_password(self):
		return check_password_hash(self.password_hash, self.password)



class LoginForm(FlaskForm):
	username = StringField('Username', validators=[DataRequired()])
	password = PasswordField('Password', validators=[DataRequired()])
	submit = SubmitField('submit')

# @app.route('/add',methods=['POST','GET'])
# def add():
# 	form=RelationForm()
# 	if form.validate_on_submit():
# 		post_data= Post(title=form.title.data,content=form.content.data)
# 		user_name = User(name=form.name.data)

# 		post_data.post = user_name
# 		db.session.add(post_data)
# 		db.session.commit()
# 		flash('Data added successfully..')
# 	form.name.data=''
# 	form.title.data = ''
# 	form.content.data=''
# 	return render_template('add.html', form=form)

# @app.route('/fetch')
# def fetch():
# 	user_list = []
# 	get_data = Post.query.all()

# 	for u in get_data:
# 		data = {
# 		'name': u.user.name,
# 		'title': u.title,
# 		'content': u.content
# 		}

# 		user_list.append(data)
# 	return jsonify(user_list)


@app.context_processor
def base():
	form=SearchForm()
	return dict(form=form)

@app.route('/search', methods=['POST'])
def search():
	form=SearchForm()
	if form.validate_on_submit():
		searched = form.searched.data
		get_data = Posts.query.filter(Posts.title.like(f'%{searched}%')).all()
		if not get_data:
			flash("Data doesn't exist..")
		else:
			return render_template('search.html', form=form, get_data=get_data, searched=searched)
	form.searched.data = ''
	return render_template('search.html', form=form, get_data=get_data)


@app.route('/login', methods=['GET','POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		data = Register.query.filter_by(username=form.username.data).first()
		if data:
			if check_password_hash(data.password,form.password.data):
				login_user(data)
				return redirect(url_for('dashboard'))
			else:
				flash('Login unsuccessful, Try again!')
		else:
			flash("User doesn't exist..")
	return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
	return render_template('dashboard.html')

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
	logout_user()
	flash("You have been logged out!")
	return redirect(url_for('login'))

@app.route('/add_post', methods=['GET','POST'])
def add_post():
    form = PostForm()
    if form.validate_on_submit():
    	poster = current_user.id
    	verify = Posts.query.filter_by(title=form.title.data).first()
    	if verify:
    		flash("Data already exists..")
    	else:
        	added = Posts(title=form.title.data, content=form.content.data, poster_id=poster)
        	db.session.add(added)
        	db.session.commit()
        	flash("Data added successfully..")
        	form.title.data = ''
        	form.content.data = ''
  
    our_data = Posts.query.order_by(Posts.issue_time).all()
    return render_template('add_post.html', form=form, our_data=our_data)

6
@app.route('/add_data', methods=['GET','POST'])
def add_data():
    form = UserForm()
    if form.validate_on_submit():
        verify = Register.query.filter_by(email=form.email.data).first()
        if verify:
            flash("Data already exists..")
        else:
            if form.password.data != form.confirm_password.data:
            	flash("Passwords don't match..")
            else:
            	hashed = generate_password_hash(form.password.data)
            	added = Register(email=form.email.data, password=hashed, username=form.username.data)
            	db.session.add(added)
            	db.session.commit()
            	flash("Data added successfully..")
      
        form.email.data = ''
        form.password.data = ''
        form.username.data = ''
        form.confirm_password.data = ''

    our_data = Register.query.order_by(Register.issue_time).all()
    return render_template('add_user.html', form=form, our_data=our_data)

@app.route('/delete_data/<int:id>', methods=['GET','POST'])
def delete_data(id):
	data = Posts.query.get(id)
	if data:
		if current_user.id == data.poster_id:
			db.session.delete(data)
			db.session.commit()
			flash("Data deleted successfully.")
		else:
			flash("You can't delete other's post..")
	else:
		flash("Record not found..")

	return redirect(url_for('add_post'))



@app.route('/update_post/<int:id>', methods=['GET', 'POST'])
def update_post(id):
    form = PostForm()
    data = Posts.query.get_or_404(id)  # Retrieve the post data
    
    if current_user.id != data.poster_id:
        flash("You can't update this post!")
        return redirect(url_for('get_post'))

    if form.validate_on_submit():
        data.title = form.title.data
        data.content = form.content.data
        db.session.commit()
        flash("Data updated successfully!")
        return redirect(url_for('get_post'))

    if request.method == 'GET':
        form.title.data = data.title
        form.content.data = data.content

    return render_template('update_post.html', form=form)


@app.route('/update_data/<id>', methods=['GET','POST'])
def update_data(id):
	form = UserForm3()
	data = Register.query.get(id)

	if request.method == 'POST':
		pas = form.password_hash.data 
		final_ps = generate_password_hash(pas)
		if data:
			data.email = form.email.data 
			data.password = final_ps
			data.username = form.username.data
			db.session.commit()
			flash("Data updated successfully..")
		else:
			flash("Data doesn't exist..")
			return redirect(url_for('add_data'))
	
	form.email.data = ''
	form.password_hash.data = ''
	form.username.data = ''
	return render_template('udpate_user.html',form=form,email=data.email, password=data.password, username=data.username)

@app.route('/admin', methods = ['GET','POST'])
@login_required
def admin():
	if current_user.id==4:
		return render_template('admin.html')
	else:
		flash("You must be an admin to access this page!!")
		return redirect(url_for('admin'))


@app.route('/get_post', methods=['GET','POST'])
def get_post():
	data = Posts.query.order_by(Posts.issue_time)
	return render_template('delete_user.html',data=data)


if __name__ == '__main__':
	app.run(debug=True)