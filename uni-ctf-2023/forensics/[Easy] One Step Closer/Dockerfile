FROM python:3.9-alpine
EXPOSE 5000
RUN addgroup -S ctf && adduser -S ctf -G ctf
COPY ./src /web
WORKDIR /web
RUN chown -R ctf:ctf /web
USER ctf
RUN pip3 install flask
ENTRYPOINT [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]