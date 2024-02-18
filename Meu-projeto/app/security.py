from werkzeug.security import generate_password_hash, check_password_hash

def generate_password_hash(password):
    return generate_password_hash(password)

def check_password_hash(hashed_password, password):
    return check_password_hash(hashed_password, password)
