FROM golang:latest

WORKDIR /go/src/app
COPY api.go api.go
RUN go env
RUN go get -d -v ./...
RUN go install -v ./...
RUN go build api.go
RUN echo $PATH
ENTRYPOINT [ "app" ]