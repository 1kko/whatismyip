PROJECT_NAME = "whatismyip"

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
	docker run --rm -it -p 8000:8000 --name ${PROJECT_NAME} --env-file .env -v $(PWD)/data:/app/data ${PROJECT_NAME}:latest

serve:
	echo "stopping previous container"
	-docker stop ${PROJECT_NAME}
	echo "removing ${PROJECT_NAME}"
	-docker container rm ${PROJECT_NAME}
	echo "start running"
	docker run -d --restart unless-stopped -p 8000:8000 --name ${PROJECT_NAME} --env-file .env -v $(PWD)/data:/app/data ${PROJECT_NAME}:latest

shell:
	docker exec -it ${PROJECT_NAME}:latest /bin/bash

clean:
	dokcer image prune -f
	# rm -rf __pycache__/ data email.db ${PROJECT_NAME}.tar

export:
	docker save -o ${PROJECT_NAME}.tar ${PROJECT_NAME}:latest
	echo "Docker image saved as ${PROJECT_NAME}.tar"

