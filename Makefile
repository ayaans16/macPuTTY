build:
	docker compose up --build -d
	cd electron && npm install
	cd electron && npm start
health:
	docker compose ps
	curl http://127.0.0.1:5050/health

