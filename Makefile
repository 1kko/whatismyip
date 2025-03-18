PROJECT_NAME := $(shell \
	if [ -f pyproject.toml ]; then \
		PROJECT_FROM_PROJECT=$$(awk '/^\[project\]/{flag=1; next} /^\[/{flag=0} flag && /^name *=/{gsub(/name *= *"|"/, "", $$0); gsub(/ /, "", $$0); print}' pyproject.toml); \
		if [ -n "$$PROJECT_FROM_PROJECT" ]; then \
			echo "$$PROJECT_FROM_PROJECT"; \
		else \
			PROJECT_FROM_POETRY=$$(awk '/^\[tool\.poetry\]/{flag=1; next} /^\[/{flag=0} flag && /^name *=/{gsub(/name *= *"|"/, "", $$0); gsub(/ /, "", $$0); print}' pyproject.toml); \
			if [ -n "$$PROJECT_FROM_POETRY" ]; then \
				echo "$$PROJECT_FROM_POETRY"; \
			else \
				echo "myproject"; \
			fi; \
		fi; \
	else \
		echo "myproject"; \
	fi \
)

all:
	docker image prune -f
	docker build -t ${PROJECT_NAME} .

build:
	docker image prune -f
	docker build -t ${PROJECT_NAME} .

run:
	echo "stopping previous container"
	-docker stop ${PROJECT_NAME}
	echo "removing ${PROJECT_NAME}"
	-docker container rm ${PROJECT_NAME}
	echo "start running"
	docker run --rm -it -p 8000:8000 --name ${PROJECT_NAME} -v $(PWD)/data:/app/data ${PROJECT_NAME}:latest

serve:
	echo "stopping previous container"
	-docker stop ${PROJECT_NAME}
	echo "removing ${PROJECT_NAME}"
	-docker container rm ${PROJECT_NAME}
	echo "start running"
	docker run -d --restart unless-stopped -p 8000:8000 --name ${PROJECT_NAME} -v $(PWD)/data:/app/data ${PROJECT_NAME}:latest

shell:
	docker exec -it ${PROJECT_NAME}:latest /bin/bash

clean:
	dokcer image prune -f
	# rm -rf __pycache__/ data email.db ${PROJECT_NAME}.tar

logs:
	docker logs -f ${PROJECT_NAME}

export:
	docker save -o ${PROJECT_NAME}.tar ${PROJECT_NAME}:latest
	echo "Docker image saved as ${PROJECT_NAME}.tar"

