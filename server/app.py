
#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def check_if_logged_in():
    open_access_list = [
        'signup',
        'login',
        'check_session'
    ]

    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401


class Signup(Resource):
    
    def post(self):

        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')
        image_url = request_json.get('image_url')
        bio = request_json.get('bio')

        user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )

        # the setter will encrypt this
        user.password_hash = password

        try:

            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return user.to_dict(), 201

        except IntegrityError:

            return {'error': '422 Unprocessable Entity'}, 422

class CheckSession(Resource):

    def get(self):
        
        user_id = session['user_id']
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        
        return {}, 401


class Login(Resource):
    
    def post(self):

        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')

        user = User.query.filter(User.username == username).first()

        if user:
            if user.authenticate(password):

                session['user_id'] = user.id
                return user.to_dict(), 200

        return {'error': '401 Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        session['user_id'] = None        
        return {}, 204
        

class RecipeIndex(Resource):
    def get(self):
        user = User.query.filter_by(id=session.get('user_id')).first()
        if not user:
            return {'error': '401 Unauthorized'}, 401
        return [recipe.to_dict() for recipe in user.recipes], 200        
        
    def post(self):
        request_json = request.get_json()

        # 🔍 Validate request data
        title = request_json.get('title')
        instructions = request_json.get('instructions')
        minutes_to_complete = request_json.get('minutes_to_complete')

        # 🔥 Check for missing or invalid data before hitting the database
        if not title or not instructions or minutes_to_complete is None:
            return {'error': 'Missing required fields'}, 422

        if len(instructions) < 50:
            return {'error': 'Instructions must be at least 50 characters long'}, 422

        # 🔍 Ensure user is authenticated
        user_id = session.get('user_id')
        if not user_id:
            return {'error': '401 Unauthorized'}, 401

        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id,
            )

            db.session.add(recipe)
            db.session.commit()

            return recipe.to_dict(), 201

        except IntegrityError:
            db.session.rollback()  # 🔥 Prevent database corruption
            return {'error': '422 Unprocessable Entity'}, 422



api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)