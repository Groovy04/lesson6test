from flask import Flask, render_template, request, flash

#----------------------------------WTF Forms

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, IntegerField, SelectField, TextAreaField, ValidationError
from wtforms.fields.simple import PasswordField
from wtforms.validators import DataRequired, Email, InputRequired, Optional
from wtforms.fields.core import DateField, RadioField

class myform(FlaskForm):
    name = StringField("Enter your name please..", validators=[DataRequired()]) #  ,validators=[InputRequired()]  #Burada forma bir bilgi girmemizi isteyecek.
    
    email = StringField("Enter your email please..", validators=[Email()] )
    age = IntegerField("Enter your age please..", validators=[Optional()]) # ,validators=[DataRequired() This field is required , validators=[InputRequired()]
    education = SelectField(label='Education Status', choices=[("Primary School", "Primary School"),("High School", "High School"), ("University", "University")])
    additional_notes  =  TextAreaField("Ek notlar...")
    #add a datetime field


    submit = SubmitField("Send")

class myloginform(FlaskForm):
    email = StringField("Enter your email please..", validators=[Email()] )
    password = PasswordField("Enter your password please..", validators=[DataRequired()]) 

    submit = SubmitField("Send")