# pyFS Module 
Simple Wrapper for Forescout WebAPIs/DEX Module 

I've Dockerized this module to simplfy deployment - you just need a host with docker which have reachability to your Forescout CounterACT running the WebAPIs / DEX Module. Ensure you have allowed the IP fo the host running  docker to access both WebAPIs / DEX Modules. 

## 1. Initialization on the Docker host 

 Pull the code from GitHub via git clone command:
 
```
git clone https://github.com/hkarhani/pyfs.git

```

## 2. Create your own Docker container 

Change directory to pyfs and Build your local container. 

```
cd pyfs 

docker build -t pyfscontainer .
```

and then verify if the image exist in docker images: 

```
$ docker images

REPOSITORY                     TAG                 IMAGE ID            CREATED             SIZE
pyfscontainer                 latest              d8cbfda2879c        45 seconds ago      344MB
```

## 3. Run the Docker container

Run container and choose the port to expose Jupyter Notebook on (in the following example - the host will be exposing port 8899) while the internal port exposed by the container is 8888. 

```
$ docker run -d --name pyfs -p 8899:8888 pyfscontainer 

a1530186072b867d8c2f16a586b23ec868862e5e07cf7d7c1d0df17712a6f666
```

Verify that the container is running in background using docker ps command: 

```
$ docker ps 

CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                               NAMES
a1530186072b        pyfscontainer       "/bin/sh -c '/bin/sh…"   3 seconds ago       Up 2 seconds        0.0.0.0:8899->8888/tcp              pyfs
```

## 4. Access Jupyter Notebook 

Open your Browser and browse to the Host IP with port 8899 

```
http://<docker-host-ip>:8899/
```

Voila! 

## 5. Edit fsconfig.yml file 

Before loading the Sample pyFS-Lists Notebook - ensure you edit the fsconfig.yml file in Jupyter Notebook.

Edit fsconfig.yml YALM file to match your CounterACT IP / username / Pass for both WebAPIs & DEX: 

```
---
counterActIP: 10.0.0.200 	# Forescout EM / CT IP
Web-API:			# WebAPI Settings 
    User: lab 			# Username of WebAPI 
    Password: strongpass 	# Password of WebAPI 
DEX-Web-Serivces: 		# DEX Web Services Settings 
    User: lab@lab 		# User of DEX Account in format: <name>@<username> 
    Password: strongpass 	# Password of DEX Account 
```

## 6. Load your pyFS-Lists notebook and Enjoy!

 Via NoteBook Web interface click on pyFS-Lists.ipynb notebook to begin executing the Cells (shift-Enter to execute the cells)
 
 You can edit the lists name as created by your CounterACT (please refer to each section comments) in each cell before executing it. 


## 7. Stopping & Removing the Ctonainer 

Stop the Docker Container: 

```
$ docker stop pyfs

pyfs
```

Remove the Docker Container: 

```
$ docker rm pyfs 

pyfs
```

Remove the created Docker Container: 

```
$ docker rmi pyfscontainer 

Untagged: pyfscontainer:latest
Deleted: sha256:d8cbfda2879c6031847950d321ba2a4d4389c79b1a50b2895a719c509e66ffe8
Deleted: sha256:c3713797120b7a1340b5d7f4bbb2d55575546a84e77398e2de224c3d721cf0b0
Deleted: sha256:0d7dd2b0d2d781cd74b15ef14afb6f6eacee1c545fd10cc8a4b0316845518d9d
Deleted: sha256:78db07ebdad90d37b53b0c878c34a3f86386eec68adbdec06c43f732997cb5b0
```