---
title: Docker Cheat Sheet
description: 
published: true
date: 2021-08-15T17:16:43.753Z
tags: cheatsheet, security, docker
editor: markdown
dateCreated: 2021-08-15T17:16:43.753Z
---

# Docker Cheat Sheet
**Running Container**
sudo docker container ls
sudo docker ps

**Start container**
docker run [containerName/ID]

**Start container + attach bash**
docker run -it [contiainerName/ID] sh

**Copy File from running container to host**
docker cp <containerId>:/file/path/within/container /host/path/target

**Stop container**
docker kill [ID]

**Build Image from DOCKERFILE**
docker build -t DOCKERFILE

**Display Docker images**
docker images
docker images -a

**Delete docker images**
docker image rm -f [ImageID]

**See under which user the container is launched**
docker inspect $(docker ps -q) --format '{{.Config.User}} {{.Name}}'
