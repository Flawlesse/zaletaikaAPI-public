# PROD
build:
	docker-compose -f docker-compose-prod.yml build --build-arg UNAME=$$(whoami) \
		--build-arg UID=$$(id -u) --build-arg GID=$$(id -g) --progress=plain
run:
	docker-compose -f docker-compose-prod.yml up -d
stop:
	docker-compose -f docker-compose-prod.yml down
migrate:
	docker exec --tty $$(docker-compose -f docker-compose-prod.yml ps -q api) python manage.py makemigrations;\
	docker exec --tty $$(docker-compose -f docker-compose-prod.yml ps -q api) python manage.py migrate

# DEV
build-testimage:
	docker-compose -f docker-compose-test.yml build --build-arg UNAME=$$(whoami) \
		--build-arg UID=$$(id -u) --build-arg GID=$$(id -g) --progress=plain
migrate-local:
	docker exec -it $$(docker-compose -f docker-compose-test.yml ps -q api) python manage.py makemigrations;\
	docker exec -it $$(docker-compose -f docker-compose-test.yml ps -q api) python manage.py migrate
run-local:
	docker-compose -f docker-compose-test.yml up -d;\
	docker exec --tty $$(docker-compose -f docker-compose-test.yml ps -q api) \
		python -m gunicorn --bind 0.0.0.0:8000 --workers 4 config.wsgi:application &
stop-local:
	docker-compose -f docker-compose-test.yml down
test:
	docker-compose -f docker-compose-test.yml run api python -m pytest;\
	docker-compose -f docker-compose-test.yml down
lint:
	pre-commit run --all-files

# FOR AWS LINUX
clear-docker-cache:
	docker system prune -a
