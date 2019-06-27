FROM hkarhani/p3nb

MAINTAINER Hassan El Karhani <hkarhani@gmail.com>

CMD pip install PyYaml requests

ADD . /notebooks

WORKDIR /notebooks