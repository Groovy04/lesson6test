#from flask import Flask, render_template, flash, request, url_for, redirect, send_file
from flask import Flask, render_template, request, flash, redirect, url_for

#----------------------------------WTF Forms

#from flask_wtf import FlaskForm
#from wtforms import StringField, SubmitField, IntegerField, SelectField, TextAreaField, ValidationError
#from wtforms.validators import DataRequired, Email, InputRequired, Optional
#from wtforms.fields.core import DateField, RadioField

from forms import myform, myloginform #11.05.2022
from flask_sqlalchemy import SQLAlchemy #11.05.2022
from datetime import datetime #11.05.2022

from flask_login import UserMixin #27.05.2022
from flask_login import login_user, current_user, logout_user, login_required #27.05.2022
from flask_login import LoginManager #27.05.2022

#Login password encryption için #27.05.2022
from flask_bcrypt import Bcrypt


app = Flask(__name__)

#Secret key - for hidden_tag in html
app.config['SECRET_KEY'] = "mysecret_key" 
#Kaldırır isek HTML içerisinde Runtime error verecek ve CSRF için secret key gerekiyor diyecek.

#11.05.2022
#app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://USERNAME:PASSWORD.HOST_IP/tansubaktiran"
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://tansubaktiran:Avz9p9&9Dgsu_099@193.111.73.99/tansubaktiran"
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'


#11.05.2022
#Database connection and object creation
db = SQLAlchemy(app) #Defining the db object


#Setting up user login parts #27.05.2022 - Login için
login_manager = LoginManager(app)
login_manager.login_view = 'login' #For directing to a please log in page. Otherwise throws a system error.
login_manager.login_message_category = 'info' #Optional?

#USER LOGIN FUNCTION - #27.05.2022 - Login için
@login_manager.user_loader
def load_user(id):
    return lesson4_users_db.query.get(int(id)) 

bcrypt = Bcrypt(app) #27.05.2022 Şifre encryption için gerekli.

class lesson4_db(db.Model): #11.05.2022 - our first database table -Nullable'lar eklenecek.
    id = db.Column(db.Integer, primary_key=True) #data type, Nullable, primary_key, parameters according to data_type (Ex:String length)
    name_db = db.Column(db.String(200))
    email_db = db.Column(db.String(200))
    age_db = db.Column(db.Integer)
    education_db = db.Column(db.String(200))
    notes_db = db.Column(db.String(200))
    experience_db = db.Column(db.String(200))
    record_time_db = db.Column(db.DateTime, default=datetime.utcnow)
    #initial_status_db = db.Column(db.String(20), nullable=True) #Örnek nullable
        
    def __repr__(self):
        return '<Name %r>' % self.id

class lesson4_users_db(db.Model, UserMixin): #27.05.2022 - Login için  ////  Dikkat!! UserMixin UNUTMAYINIZ
    id = db.Column(db.Integer, primary_key=True)
    name_db = db.Column(db.String(200))
    email_db = db.Column(db.String(200))
    password_db = db.Column(db.String(100))
        
    def __repr__(self):
        return '<Name %r>' % self.id


@app.route('/', methods=["GET", "POST"]) #, methods=["GET", "POST"] # Sıkça rastlanan bir hata olabiliyor. POST unutuluyor. BİR
@app.route('/index', methods=["GET", "POST"]) #, methods=["GET", "POST"]
def index():
    form = myform()
    name_entered = None
    email_entered = None
    age_entered = None
    education_entered = None
    notes_entered = None
    

    if request.method=="POST":
        if form.validate_on_submit(): # Opsiyon 3 - Özellikle formun bazı bilgiler ile dolu olmasını istiyor isek bu mekanizma faydalı.
            name_entered = form.name.data
            email_entered = form.email.data
            age_entered = form.age.data
            education_entered = form.education.data
            notes_entered = form.additional_notes.data     

            new_record = lesson4_db(#11.05.2022       

                name_db = form.name.data,
                email_db = form.email.data,
                age_db = form.age.data,
                education_db = form.education.data,
                notes_db = form.additional_notes.data)
                
            #Buraya try_except ekleyelim. 11.05.2022
            try:            
                db.session.add(new_record)
                db.session.commit()
                flash("Girdiğiniz kayıt başarıyla database'e kaydedildi...", "success") #Flash mesaj demosu
            except:
                flash("Bilgi kayıt aşamasında bir sorun oluştu.", "success") 
                


    if request.method=="GET": # Opsiyon 3 -devamı - Özellikle formun bazı bilgiler ile dolu olmasını istiyor isek bu mekanizma faydalı.

        #form.name.data = "naber nasılsınız?"
        print("Opsiyon 3 - GET method")
        #flash("Bu ekrana GET metodu ile ulaştınız. ", "success") #Flash mesaj demosu

    return render_template("index.html", form=form, name_entered=name_entered, email_entered=email_entered, age_entered=age_entered, education_entered=education_entered,notes_entered=notes_entered) #, email_entered=email_entered, age_entered=age_entered, education_entered=education_entered,notes_entered=notes_entered

#11.05.2022
#Show all entries - done
#See one entry  - done
#Update one entry - from all records screen - done
#Delete one entry - from all records screen  - done

@app.route('/show_all') #To be deleted #11.05.2022 - modified
@login_required #27.05.2022
def show_all():

    all_records = lesson4_db.query.all()
    #str_staff_db.query.filter_by(id=active_user_id).first()
    #lesson4_db.query.order_by(lesson4_db.id).all()
    

    return render_template("show_all.html", all_records=all_records)


@app.route('/show_one/<int:id>') #To be deleted #11.05.2022
def show_one(id): #id parametre olarak burada unutulabiliyor!! #11.05.2022

    record_to_show = lesson4_db.query.filter_by(id=id).first()
    #lesson4_db.query.order_by(lesson4_db.id).all()

    return render_template("show_one.html", record_to_show=record_to_show)

@app.route('/delete_one/<int:id>') #To be deleted #11.05.2022
def delete_one(id): #id parametre olarak burada unutulabiliyor!! #11.05.2022

    record_to_delete = lesson4_db.query.filter_by(id=id).first()
    db.session.delete(record_to_delete)
    db.session.commit() #Commit çoğu zaman unutulabiliyor.
    all_records = lesson4_db.query.all()

    return render_template("show_all.html", all_records=all_records)

@app.route('/update_one/<int:id>', methods=["GET", "POST"]) #To be deleted #11.05.2022
@login_required
def update_one(id): #id parametre olarak burada unutulabiliyor!! #11.05.2022

    record_to_update = lesson4_db.query.filter_by(id=id).first()
    form = myform()
    if request.method == "POST":
        #form = myform()
        record_to_update.name_db = form.name.data   #request.form["name"]
        print("ID to be updated :", record_to_update.id)
        record_to_update.email_db = form.email.data
        record_to_update.age_db = form.age.data
        record_to_update.education_db = form.education.data
        record_to_update.notes_db = form.additional_notes.data
        try:
            db.session.commit()
            flash("Müşteri bilgileri başarıyla güncellendi.", "success")
            all_records = lesson4_db.query.all()
            return render_template("show_all.html", record_to_update = record_to_update, form=form, all_records=all_records)
        except:
            flash("Müşteri bilgilerinin güncellenmesinde bir sorun oluştu! Lütfen IT Yöneticisine bilgi veriniz.", "success")
            return render_template("show_all.html", record_to_update = record_to_update, form=form, all_records=all_records)
        
        #return render_template("update_one.html", record_to_update = record_to_update, form=form)

    if request.method == "GET":
        #form = myform()
        form.name.data = record_to_update.name_db
        form.email.data = record_to_update.email_db
        form.age.data = record_to_update.age_db
        form.education.data = record_to_update.education_db
        form.additional_notes.data = record_to_update.notes_db
        print("ID to be updated :", record_to_update.id)

        return render_template("update_one.html", record_to_update = record_to_update, form=form)
    
    

@app.route("/login", methods=['GET', 'POST']) #27.05.2022
def login():

    if current_user.is_authenticated:
        print("User is already logged in")
        return redirect(url_for('index'))
    
    form = myloginform()
    
    if form.validate_on_submit():
                
        print("Form validated")
        user = lesson4_users_db.query.filter_by(email_db=form.email.data).first()
        #TB Not : Atölyede bu konuya bir bakalım. #27.05.2022
        # Eğer şifre doğru olsa bile aranan user'in emaili yanlış ise hata veriyordu çünkü user objesini bulamadığı için 
        # o userın emailini de bulamıyordu. passsword_db attribute yok diyordu. Bu şekilde if kontrolü ile çalışıyor.
        if user:
            password = user.password_db
            print("passcheck hashed", password, "user name : ", user.name_db)
            
            password_check = bcrypt.check_password_hash(password, form.password.data) #Boolean getiriyor. True ise bir alttaki if içerisinde user'i login ediyoruz. #27.05.2022
            print(password_check)
            #print("passcheck", password_check)
        
        if user and password_check:
            print("Pass Check", password_check)
            print("/// Found this user and his password is correct!!! /// Password Hashing technique is used!! I am logging the user in ;) /// ")
            login_user(user)
            
            print("User seems to be logged in now..")
            flash('You have successfully logged in. Have a nice day.', 'success')
            
            return redirect(url_for('show_all'))
            
        else:
            flash('There has been a problem during logging in. Please check your username and password', 'error')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout") #27.05.2022
def logout():
    if current_user.is_authenticated:
        
        logout_user()
        print("The user should have been LOGGED OUT NOW!!!")
        flash('You have successfully logged out. Have a nice day.', 'success')
    return redirect(url_for('show_all'))



if __name__ == "__main__":
    app.run(debug=True)

