import os
import secrets
import requests
import time
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort
from home import app, db, bcrypt, mail
from home.forms import RegistrationForm, LoginForm, UpdateAccountForm, RequestResetForm, ResetPasswordForm, PostForm
from home.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message


@app.route("/")
@app.route("/home")
def home():
    posts = Post.query.all()
    response = requests.get("https://api.coinbase.com/v2/prices/ETH-USD/spot")
    responses = requests.get("https://api.coinbase.com/v2/prices/BTC-USD/spot")
    responsess = requests.get("https://api.coinbase.com/v2/prices/XRP-EUR/spot")
    data = response.json()
    data2 = responses.json()
    data3 = responsess.json()
    ETH = data["data"]["base"]
    price = data["data"]["amount"]
    print(f"Ethereum : {ETH}  Price: {price}")

    BTC = data2["data"]["base"]
    price2 = data2["data"]["amount"]
    print(f"BitCoin : {BTC}  Price: {price2}")

    XRP = data3["data"]["base"]
    price3 = data3["data"]["amount"]
    print(f"Ripple : {XRP}  Price: {price3}")

    return render_template('home.html', posts=posts, price=price, price2=price2, price3=price3)


@app.route("/about")
def about():
    response = requests.get("https://api.coinbase.com/v2/prices/ETH-USD/spot")
    responses = requests.get("https://api.coinbase.com/v2/prices/BTC-USD/spot")
    responsess = requests.get("https://api.coinbase.com/v2/prices/XRP-EUR/spot")
    data = response.json()
    data2 = responses.json()
    data3 = responsess.json()
    ETH = data["data"]["base"]
    price = data["data"]["amount"]
    print(f"Ethereum : {ETH}  Price: {price}")

    BTC = data2["data"]["base"]
    price2 = data2["data"]["amount"]
    print(f"BitCoin : {BTC}  Price: {price2}")

    XRP = data3["data"]["base"]

    price3 = data3["data"]["amount"]

    print(f"Ripple : {XRP}  Price: {price3}")

    return render_template('about.html', title='About', price=price, price2=price2, price3= price3)


@app.route("/register", methods=['GET', 'POST'])
def register():
    response = requests.get("https://api.coinbase.com/v2/prices/ETH-USD/spot")
    responses = requests.get("https://api.coinbase.com/v2/prices/BTC-USD/spot")
    responsess = requests.get("https://api.coinbase.com/v2/prices/XRP-EUR/spot")
    data = response.json()
    data2 = responses.json()
    data3 = responsess.json()
    ETH = data["data"]["base"]
    price = data["data"]["amount"]
    print(f"Ethereum : {ETH}  Price: {price}")

    BTC = data2["data"]["base"]
    price2 = data2["data"]["amount"]
    print(f"BitCoin : {BTC}  Price: {price2}")

    XRP = data3["data"]["base"]
    price3 = data3["data"]["amount"]
    print(f"Ripple : {XRP}  Price: {price3}")

    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form, price=price , price2=price2, price3=price3)


@app.route("/login", methods=['GET', 'POST'])
def login():
    response = requests.get("https://api.coinbase.com/v2/prices/ETH-USD/spot")
    responses = requests.get("https://api.coinbase.com/v2/prices/BTC-USD/spot")
    responsess = requests.get("https://api.coinbase.com/v2/prices/XRP-EUR/spot")
    data = response.json()
    data2 = responses.json()
    data3 = responsess.json()
    ETH = data["data"]["base"]
    price = data["data"]["amount"]
    print(f"Ethereum : {ETH}  Price: {price}")

    BTC = data2["data"]["base"]
    price2 = data2["data"]["amount"]
    print(f"BitCoin : {BTC}  Price: {price2}")

    XRP = data3["data"]["base"]
    price3 = data3["data"]["amount"]
    print(f"Ripple : {XRP}  Price: {price3}")

    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form , price=price , price2=price2, price3=price3)


@app.route("/logout")
def logout():

    logout_user()
    return redirect(url_for('home'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    response = requests.get("https://api.coinbase.com/v2/prices/ETH-USD/spot")
    responses = requests.get("https://api.coinbase.com/v2/prices/BTC-USD/spot")
    responsess = requests.get("https://api.coinbase.com/v2/prices/XRP-EUR/spot")
    data = response.json()
    data2 = responses.json()
    data3 = responsess.json()
    ETH = data["data"]["base"]
    price = data["data"]["amount"]
    print(f"Ethereum : {ETH}  Price: {price}")

    BTC = data2["data"]["base"]
    price2 = data2["data"]["amount"]
    print(f"BitCoin : {BTC}  Price: {price2}")

    XRP = data3["data"]["base"]
    price3 = data3["data"]["amount"]
    print(f"Ripple : {XRP}  Price: {price3}")

    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form , price=price , price2=price2, price3=price3)


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    response = requests.get("https://api.coinbase.com/v2/prices/ETH-USD/spot")
    responses = requests.get("https://api.coinbase.com/v2/prices/BTC-USD/spot")
    responsess = requests.get("https://api.coinbase.com/v2/prices/XRP-EUR/spot")
    data = response.json()
    data2 = responses.json()
    data3 = responsess.json()
    ETH = data["data"]["base"]
    price = data["data"]["amount"]
    print(f"Ethereum : {ETH}  Price: {price}")

    BTC = data2["data"]["base"]
    price2 = data2["data"]["amount"]
    print(f"BitCoin : {BTC}  Price: {price2}")

    XRP = data3["data"]["base"]
    price3 = data3["data"]["amount"]
    print(f"Ripple : {XRP}  Price: {price3}")

    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user, currency=form.currency.data,
                    quantity=form.quantity.data)
        db.session.add(post)
        db.session.commit()
        flash('Pruchase done!', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Purchase',
                           form=form, legend='Purchase', price=price, price2=price2, price3=price3)


@app.route("/post/<int:post_id>")
def post(post_id):
    response = requests.get("https://api.coinbase.com/v2/prices/ETH-USD/spot")
    responses = requests.get("https://api.coinbase.com/v2/prices/BTC-USD/spot")
    responsess = requests.get("https://api.coinbase.com/v2/prices/XRP-EUR/spot")
    data = response.json()
    data2 = responses.json()
    data3 = responsess.json()
    ETH = data["data"]["base"]
    price = data["data"]["amount"]
    print(f"Ethereum : {ETH}  Price: {price}")

    BTC = data2["data"]["base"]
    price2 = data2["data"]["amount"]
    print(f"BitCoin : {BTC}  Price: {price2}")

    XRP = data3["data"]["base"]
    price3 = data3["data"]["amount"]
    print(f"Ripple : {XRP}  Price: {price3}")



    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post , price=price , price2=price2, price3=price3,)


@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    response = requests.get("https://api.coinbase.com/v2/prices/ETH-USD/spot")
    responses = requests.get("https://api.coinbase.com/v2/prices/BTC-USD/spot")
    responsess = requests.get("https://api.coinbase.com/v2/prices/XRP-EUR/spot")
    data = response.json()
    data2 = responses.json()
    data3 = responsess.json()
    ETH = data["data"]["base"]
    price = data["data"]["amount"]
    print(f"Ethereum : {ETH}  Price: {price}")

    BTC = data2["data"]["base"]
    price2 = data2["data"]["amount"]
    print(f"BitCoin : {BTC}  Price: {price2}")

    XRP = data3["data"]["base"]
    price3 = data3["data"]["amount"]
    print(f"Ripple : {XRP}  Price: {price3}")

    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        post.currency = form.currency.data
        post.quantity = form.quantity.data
        db.session.commit()
        flash('Your purchase has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
        form.currency.data = post.currency
        form.quantity.data = post.quantity
    return render_template('create_post.html', title='Update Purchase',
                           form=form, legend='Update Purchase',  price=price, price2=price2, price3=price3)


@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    response = requests.get("https://api.coinbase.com/v2/prices/ETH-USD/spot")
    responses = requests.get("https://api.coinbase.com/v2/prices/BTC-USD/spot")
    responsess = requests.get("https://api.coinbase.com/v2/prices/XRP-EUR/spot")
    data = response.json()
    data2 = responses.json()
    data3 = responsess.json()
    ETH = data["data"]["base"]
    price = data["data"]["amount"]
    print(f"Ethereum : {ETH}  Price: {price}")

    BTC = data2["data"]["base"]
    price2 = data2["data"]["amount"]
    print(f"BitCoin : {BTC}  Price: {price2}")

    XRP = data3["data"]["base"]
    price3 = data3["data"]["amount"]
    print(f"Ripple : {XRP}  Price: {price3}")

    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your purchase has been deleted!', 'success')
    return redirect(url_for('home'))


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)




def send_reset_email(user):
    token = user.get_reset_token()
    print(str(os.environ.get('EMAIL_USER')))
    msg = Message('Password Reset Request',
                  sender='sicsrapp@gmail.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)