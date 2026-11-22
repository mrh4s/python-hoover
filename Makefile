.PHONY: test lint format install docker-build docker-run

test:
	pytest --tb=short -q

lint:
	ruff check .
	ruff format --check .

format:
	ruff format .
	ruff check --fix .

install:
	pip install -e ".[dev]"

docker-build:
	docker build -t python-hoover .

docker-run:
	docker run --rm -it --net=host --privileged python-hoover
