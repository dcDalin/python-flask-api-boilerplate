# project/server/auth/views.py
"""Auth view endpoint routes"""


from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView
from project.server import BCRYPT, DB
from project.server.auth.models import User, BlacklistToken

AUTH_BLUEPRINT = Blueprint('auth', __name__)


class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        """User registration method"""
        # get the post data
        post_data = request.get_json()
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:

            user = User(
                email=post_data.get('email'),
                password=post_data.get('password')
            )
            # insert the user
            DB.session.add(user)
            DB.session.commit()
            # generate the auth token
            auth_token = user.encode_auth_token(user.id)
            response_object = {
                'status': 'success',
                'message': 'Successfully registered.',
                'auth_token': auth_token.decode()
            }
            return make_response(jsonify(response_object)), 201
        else:
            response_object = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(response_object)), 202


class LoginAPI(MethodView):
    """
    User Login Resource
    """

    def post(self):
        """Login post method"""
        # get the post data
        post_data = request.get_json()

        # fetch the user data
        user = User.query.filter_by(
            email=post_data.get('email')
        ).first()
        if user and BCRYPT.check_password_hash(user.password,
                                               post_data.get('password')):
            auth_token = user.encode_auth_token(user.id)
            if auth_token:
                response_object = {
                    'status': 'success',
                    'message': 'Successfully logged in.',
                    'auth_token': auth_token.decode()
                }
                return make_response(jsonify(response_object)), 200
        else:
            response_object = {
                'status': 'fail',
                'message': 'User does not exist.'
            }
            return make_response(jsonify(response_object)), 404


class UserAPI(MethodView):
    """
    User Resource
    """

    def get(self):
        """Get user details method"""
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                auth_token = auth_header.split(" ")[1]
            except IndexError:
                response_object = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(response_object)), 401
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                response_object = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'admin': user.admin,
                        'registered_on': user.registered_on
                    }
                }
                return make_response(jsonify(response_object)), 200
            response_object = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(response_object)), 401
        else:
            response_object = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(response_object)), 401


class LogoutAPI(MethodView):
    """
    Logout Resource
    """

    def post(self):
        """Logout user method"""
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        if auth_token:
            resp = User.decode_auth_token(auth_token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklist_token = BlacklistToken(token=auth_token)

                # insert the token
                DB.session.add(blacklist_token)
                DB.session.commit()
                response_object = {
                    'status': 'success',
                    'message': 'Successfully logged out.'
                }
                return make_response(jsonify(response_object)), 200

            else:
                response_object = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(response_object)), 401
        else:
            response_object = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(response_object)), 403


# define the API resources
REGISTRATION_VIEW = RegisterAPI.as_view('register_api')
LOGIN_VIEW = LoginAPI.as_view('login_api')
USER_VIEW = UserAPI.as_view('user_api')
LOGOUT_VIEW = LogoutAPI.as_view('logout_api')

# add Rules for API Endpoints
AUTH_BLUEPRINT.add_url_rule(
    '/auth/register',
    view_func=REGISTRATION_VIEW,
    methods=['POST']
)
AUTH_BLUEPRINT.add_url_rule(
    '/auth/login',
    view_func=LOGIN_VIEW,
    methods=['POST']
)
AUTH_BLUEPRINT.add_url_rule(
    '/auth/status',
    view_func=USER_VIEW,
    methods=['GET']
)
AUTH_BLUEPRINT.add_url_rule(
    '/auth/logout',
    view_func=LOGOUT_VIEW,
    methods=['POST']
)
