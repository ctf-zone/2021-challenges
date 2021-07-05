FROM ubuntu:20.04
WORKDIR /app
COPY src .
RUN apt-get update && apt-get install -y build-essential libssl-dev
RUN make clean && make
CMD ["./bin/raccoon-server"]
