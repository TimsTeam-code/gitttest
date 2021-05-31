import os
from datetime import datetime
from hashlib import sha256

import pymongo
from bson.objectid import ObjectId
from flask import Flask, render_template, request, redirect, session, abort, send_file
from flask_pymongo import PyMongo
from werkzeug.utils import secure_filename

from config import config
from utils import get_random_string


def allowed_file(filename):
    ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'doc', 'docx', 'txt', 'png']
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def create_app(env=os.getenv('FLASK_ENV', 'production')):
    app = Flask(__name__)
    app.config.from_object(config[env])

    app.secret_key = 'vfyuydfyfio'
    mongo = PyMongo(app)

    @app.route('/')
    def show_index():
        if not 'userToken' in session:
            session['error'] = 'You must login to access this page '
            return redirect('/login')
        # validate user token
        token_document = mongo.db.user_tokens.find_one({
            'sessionHash': session['userToken'],
        })
        if token_document is None:
            session.pop('userToken', None)
            session['error'] = 'You must login again to access this page '
            return redirect('/login')

        error = ''
        if 'error' in session:
            error = session['error']
            session.pop('error', None)

        userId = token_document['userId']
        user = mongo.db.users.find_one({
            '_id': userId,
        })
        uploaded_files = mongo.db.files.find({
            'userId': userId,
            'isActive': True

        }).sort([('createdAt', pymongo.DESCENDING)])

        return render_template('files.html', uploaded_files=uploaded_files, user=user, error=error)

    @app.route('/login')
    def show_login():
        if 'userToken' in session:
            # Validate user token from the db
            # redirect / is session is valid
            pass

        signupSuccess = ''
        if 'signupSuccess' in session:
            signupSuccess = session['signupSuccess']
            session.pop('signupSuccess', None)

        error = ''
        if 'error' in session:
            error = session['error']
            session.pop('error', None)

        return render_template('login.html', signupSuccess=signupSuccess,
                               error=error)

    @app.route('/check_login', methods=['POST'])
    def check_login():
        try:
            email = request.form['email']
        except KeyError:
            email = ''
        try:
            password = request.form['password']
        except KeyError:
            password = ''

        # Check if email is blank
        if not len(email) > 0:
            session['error'] = 'Email is required'
            return redirect('/login')

        # Check if password is blank
        if not len(password) > 0:
            session['error'] = 'Password is required'
            return redirect('/login')

        # Find email in data base
        user_document = mongo.db.users.find_one({"email": email})
        if user_document is None:
            # user document with the given email not found
            session['error'] = 'No account exists with this email address '
            return redirect('/login')

        # Verify that password hash matches with original
        password_hash = sha256(password.encode('utf-8')).hexdigest()
        if user_document['password'] != password_hash:
            session['error'] = "Password is wrong"
            return redirect('/login')

        # Generate token and save it in session
        random_string = get_random_string()
        randomSessionHash = sha256(random_string.encode('utf-8')).hexdigest()
        token_object = mongo.db.user_tokens.insert_one({
            'userId': user_document['_id'],
            'sessionHash': randomSessionHash,
            'createAt': datetime.utcnow(),
        })
        session['userToken'] = randomSessionHash

        return redirect('/')

    @app.route('/signup')
    def show_signup():
        error = ''
        if 'error' in session:
            error = session['error']
            session.pop('error', None)

        return render_template('signup.html', error=error)

    @app.route('/handle_signup', methods=['POST'])
    def handle_signup():
        try:
            email = request.form['email']
        except KeyError:
            email = ''
        try:
            password = request.form['password']
        except KeyError:
            password = ''

        # Check if email is blank
        if not len(email) > 0:
            session['error'] = 'Email is required'
            return redirect('/signup')

        # Check if email is valid
        if not '@' in email or '.' not in email:
            session['error'] = 'Email is invalid'
            return redirect('/signup')

        # Check if password is blank
        if not len(password) > 0:
            session['error'] = 'Password is required'
            return redirect('/signup')

        # check if email already exists
        matching_user_count = mongo.db.users.count_documents({"email": email})
        if matching_user_count > 0:
            session['error'] = 'Email already exists'
            return redirect('/signup')

        password = sha256(password.encode('utf-8')).hexdigest()
        # create user record in db
        result = mongo.db.users.insert_one({
            'email': email,
            'password': password,
            'name': '',
            'lastLoginDate': None,
            'createAt': datetime.utcnow(),
            'updateAt': datetime.utcnow(),
        })
        # Redirect to Login page
        session['signupSuccess'] = 'Your user account is ready.You can login now'

        return redirect('/login')

    @app.route('/logout')
    def logout_user():
        session.pop('userToken', None)
        session['signupSuccess'] = 'You are now logged out'
        return redirect('/login')

    @app.route('/handle_file_upload', methods=['POST'])
    def handle_file_upload():
        if not 'userToken' in session:
            session['error'] = 'You must login to access this page '
            return redirect('/login')
        # validate user token
        token_document = mongo.db.user_tokens.find_one({
            'sessionHash': session['userToken'],
        })
        if token_document is None:
            session.pop('userToken', None)
            session['error'] = 'You must login again to access this page '
            return redirect('/login')
        if 'uploadedFile' not in request.files:
            session['error'] = 'No file uploaded'
            return redirect('/')
        file = request.files['uploadedFile']

        if file.filename == '':
            session['error'] = 'No selected file'
            return redirect('/')

        if not allowed_file(file.filename):
            session['error'] = 'File type not allowed'
            return redirect('/')

        # File size check
        extension = file.filename.rsplit('.', 1)[1].lower()
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        result = mongo.db.files.insert_one({
            'userId': token_document['userId'],
            'originalFileName': file.filename,
            'fileType': extension,
            'filePath': filepath,
            'isActive': True,
            'createdAt': datetime.utcnow(),

        })

        return redirect('/')

    @app.route('/download/<fileId>/<fileNameSlugified>', methods=['GET'])
    def showDownloadPage(fileId, fileNameSlugified):
        if not 'userToken' in session:
            session['error'] = 'You must login to access this page '
            session['redirectToUrl'] = '/download' + fileId + '/' + fileNameSlugified
            return redirect('/login')
        # validate user token
        token_document = mongo.db.user_tokens.find_one({
            'sessionHash': session['userToken'],
        })
        if token_document is None:
            session.pop('userToken', None)
            session['error'] = 'You must login again to access this page '
            return redirect('/login')

        userId = token_document['userId']

        user = mongo.db.users.find_one({
            '_id': userId,
        })

        file_object = None
        try:
            file_object = mongo.db.files.find_one({
                '_id': ObjectId(fileId),
            })
        except:
            pass

        if file_object is None:
            return abort(404)
        return render_template('download.html', file=file_object, user=user)

    @app.route('/download_file/<fileId>', methods=['GET'])
    def downloadFile(fileId):
        if not 'userToken' in session:
            session['error'] = 'You must login to access this page '
            return redirect('/login')
        # validate user token
        token_document = mongo.db.user_tokens.find_one({
            'sessionHash': session['userToken'],
        })
        if token_document is None:
            session.pop('userToken', None)
            session['error'] = 'You must login again to access this page '
            return redirect('/login')

        file_object = None
        try:
            file_object = mongo.db.files.find_one({
                '_id': ObjectId(fileId),
            })

        except:
            pass

        if file_object is None:
            return abort(404)

        # Track user download
        userId = token_document['userId']
        mongo.db.file_downloads.insert_one({
            'fileId': file_object['_id'],
            'userId': userId,
            'createdAt': datetime.utcnow(),

        })

        filePath = file_object['filePath']
        return send_file(filePath, as_attachment=True)

    @app.route('/delete_file/<fileId>', methods=['GET', 'POST'])
    def delete_file(fileId):
        file = mongo.db.files.delete_one({
            '_id': ObjectId(fileId)
        })
        return redirect('/')

    return app


if __name__ == '__main__':
    app = create_app(os.getenv('FLASK_ENV', 'production'))
    app.run(host="0.0.0.0", port=5000, debug=True)
