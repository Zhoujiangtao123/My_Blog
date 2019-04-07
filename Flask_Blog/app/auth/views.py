# coding: utf-8
from flask import render_template, redirect, request, url_for, flash
from flask.ext.login import login_user, login_required, logout_user
from . import auth
from ..models import User
from .forms import LoginForm
# from .. import db


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # 创建用户和修改标题个性签名
        # blog = BlogInfo.query.first()
        # blog.title = (u'周江涛的博客')
        # blog.signature = (u'与其感慨路难行不如马上出发')
        # user = User(email=form.email.data, username=(u'周江涛'), password=form.password.data)
        # db.session.add(user)
        # db.session.commit()
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user)
            flash(u'登陆成功！欢迎回来，%s!' % user.username, 'success')
            return redirect(request.args.get('next') or url_for('main.index'))
        else:
            flash(u'登陆失败！用户名或密码错误，请重新登陆。', 'danger')
    if form.errors:
        flash(u'登陆失败，请尝试重新登陆.', 'danger')

    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash(u'您已退出登陆。', 'success')
    return redirect(url_for('main.index'))
