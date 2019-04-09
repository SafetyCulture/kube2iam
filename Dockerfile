FROM golang:1.10 AS build

ENV BINARY_NAME kube2iam

COPY . /go/src/github.com/jtblin/kube2iam
WORKDIR /go/src/github.com/jtblin/kube2iam

RUN make setup
RUN make cross

FROM alpine:3.7 as app

RUN apk --no-cache add \
  ca-certificates \
  iptables

COPY --from=build /go/src/github.com/jtblin/kube2iam/build/bin/linux/kube2iam /bin/kube2iam

ENTRYPOINT ["kube2iam"]
