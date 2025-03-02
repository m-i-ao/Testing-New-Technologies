from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FloatField, FileField, SubmitField
from wtforms.validators import DataRequired

class ProductForm(FlaskForm):
    name = StringField('Название', validators=[DataRequired()])
    description = TextAreaField('Описание', validators=[DataRequired()])
    price = FloatField('Цена', validators=[DataRequired()])
    image = FileField('Изображение')
    submit = SubmitField('Добавить товар')
