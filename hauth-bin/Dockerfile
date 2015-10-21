#-*- mode:conf; -*-

FROM debian:jessie
MAINTAINER Tim Dysinger <tim@fpcomplete.com>

RUN apt-get update \
 && apt-get install -y libpq-dev libgmp-dev \
 && apt-get clean

ENTRYPOINT [ "/usr/local/bin/hauth-server" ]
EXPOSE 8443
