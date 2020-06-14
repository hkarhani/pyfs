FROM hkarhani/p3nbfs

MAINTAINER Hassan El Karhani <hkarhani@gmail.com>

ADD *.py /notebooks
ADD *.ipynb /notebooks
ADD *.yml /notebooks

WORKDIR /notebooks
