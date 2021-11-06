build:
	echo "Up containers with Postgres и Redis"
	docker-compose up -d redis_auth postgres_auth auth_api
	echo "Done."

setup:
	echo "Init envs and flask-app"
	bash -c 'set -ax; source .env; set +ax;\
		PYTHONPATH=. FLASK_APP="auth_api/src/app.py:create_app()";\
		 cd src;\
		 flask run --host=$${HOST} --port=$${PORT}'
	echo "Done. Runned on - $${HOST}:$${PORT}"

demo:
	echo "Run demo scenario. Create user with email- demo@demo.com, with password - demopass"
	bash -c 'set -ax; source .env; set +ax;\
		flask create_user demo@demo.com demopass'
	echo "Done."
