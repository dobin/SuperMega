#!/usr/bin/python3

import os
import argparse
from flask import Flask
import logging

from app.views import views
from app.views_project import views_project
from app.views_shcdev import views_shcdev
from log import setup_logging
from utils import check_deps


if __name__ == "__main__":
	logging.getLogger('werkzeug').setLevel(logging.ERROR)
	setup_logging()
	check_deps()

	parser = argparse.ArgumentParser()
	parser.add_argument('--listenip', type=str, help='IP to listen on', default="0.0.0.0")
	parser.add_argument('--listenport', type=int, help='Port to listen on', default=5001)
	parser.add_argument('--debug', action='store_true', help='Debug', default=False)
	args = parser.parse_args()

	print("Listen on: {} {}".format(args.listenip, args.listenport))

	root_folder = os.path.dirname(__file__)
	app_folder = os.path.join(root_folder, 'app')

	app = Flask(__name__, 
		static_folder=os.path.join(app_folder, 'static'),
		template_folder=os.path.join(app_folder, 'templates')
	)

	#app.config['UPLOAD_FOLDER'] = os.path.join(app_folder, 'upload')
	#app.config['EXAMPLE_FOLDER'] = os.path.join(app_folder, 'examples')
	app.config['TEMPLATES_AUTO_RELOAD'] = True
	app.config['SECRET_KEY'] = os.urandom(24)
	app.config['SESSION_TYPE'] = 'filesystem'
	app.config.from_prefixed_env()
    
	app.register_blueprint(views)
	app.register_blueprint(views_project)
	app.register_blueprint(views_shcdev)
	app.run(host=args.listenip, port=args.listenport, debug=args.debug)
