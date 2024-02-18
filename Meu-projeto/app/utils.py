from flask import request, session

def get_next_page():
    return request.args.get('next') or request.referrer

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf'}
