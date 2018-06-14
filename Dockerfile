FROM jfloff/alpine-python:2.7-onbuild

# for a flask server
EXPOSE 5000
COPY ./app/ .
RUN wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz && \
	tar --strip-components=1 -xzf GeoLite2-City.tar.gz
CMD python /webapp.py --debug false --prod true
