FROM golang:latest

WORKDIR /go/src/app
COPY api.go api.go

RUN go get -d -v ./...
RUN go install -v ./...
RUN go build -o /go/bin/api api.go

ENTRYPOINT [ "/go/bin/api" ]