#-*- mode:conf; -*-

FROM debian:jessie
MAINTAINER Tim Dysinger <tim@fpcomplete.com>

RUN apt-get update \
 && apt-get install -y libpq-dev libgmp-dev \
 && apt-get clean

ENTRYPOINT [ "/usr/local/bin/example-hauth" ]
EXPOSE 8443
