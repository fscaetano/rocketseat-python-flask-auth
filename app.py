from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

# view login
login_manager.login_view = "login"


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if username and password:
        # login
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            login_user(user)
            return jsonify({"message": f"Authentication succeeded."})
    
    return jsonify({"message": "Invalid credentials."}), 400


@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": f"User logged out."})


@app.route("/user", methods=["POST"])
@login_required
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user =  User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User added successfully."})

    return jsonify({"message": "Invalid data."}), 401


@app.route("/user/<int:user_id>", methods=["GET"])
@login_required
def read_user(user_id):
    user = user_loader(user_id)
    if user:
        return jsonify({"username": user.username})        
        
    return jsonify({"message": "Invalid user_id."}), 404


@app.route("/user/<int:user_id>", methods=["PUT"])
@login_required
def update_user(user_id):
    data = request.json
    password = data.get("password")

    user = user_loader(user_id)    
    if user and password:
        user.password = password
        db.session.commit()
        
        return jsonify({"message": f"User {user_id} updated successfully."})\

    return jsonify({"message": "Invalid user_id."}), 404


@app.route("/user/<int:user_id>", methods=["DELETE"])
@login_required
def update_user(user_id):
    if user_id == current_user.id:
        return jsonify({"message": "Deletion is not allowed."}), 403
    
    user = user_loader(user_id)    
    if user:
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({"message": f"User {user_id} deleted successfully."})\

    return jsonify({"message": "Invalid user_id."}), 404


if __name__ == "__main__":
    app.run(debug=True)

