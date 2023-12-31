import os
from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite')
    )

    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)
    
    try:
        os.makedirs(app.instance_path)
    except OSError as ex:
        # print(f'An exception occured: {str(ex)}')
        pass

    @app.route('/hello')
    def hello():
        return 'hello world'

    from . import db
    from . import auth

    db.init_app(app)
    blueprints = [auth.bp, auth.bp1, auth.bp_home]

    for blueprint in blueprints:
        app.register_blueprint(blueprint)

    return app