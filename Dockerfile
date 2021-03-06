FROM golang:alpine

WORKDIR /app
COPY src .
ADD .env.enc .
ARG PASS_CHECKER
RUN apk add openssl
RUN openssl enc -d -aes-128-cbc -pbkdf2 -nosalt -k $PASS_CHECKER -in .env.enc -out .env
ENV GOROOT /usr/local/go
RUN go get  github.com/joho/godotenv
RUN cd updater && go build -o updater.go
RUN mkdir vulners-hosts
EXPOSE 8081
ENTRYPOINT ["/app/updater/updater.go"]
CMD exec /bin/sh -c "trap : TERM INT; sleep infinity & wait"
