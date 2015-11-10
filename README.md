# Build

    cd ./hauth-bin/
    stack install
    docker build -t hauth-base .
    stack image container

# Runtime

-   Consul

    The example uses default port 8500 on localhost. The easiest way
    to start this is using a docker instance.

        docker run -i -t -p 8500:8500 -h consul progrium/consul -server -bootstrap -ui-dir /ui

    Then use curl to write a kv pair to consul

        curl -X PUT -d "{\"secret\":\"supersekrat123\",\"name\":\"test\"}" http://localhost:8500/v1/kv/123

    Or the handy [consul cli](https://github.com/CiscoCloud/consul-cli) tool:

        consul-cli kv-write 123 "{\"secret\":\"supersekrat123\",\"name\":\"test\"}"

    The data about the partner name & their hmac secret goes into
    consul.  The code watches for updates from Consul.

-   Postgres

        docker run --name postgres -d -e POSTGRES_USER=hauth -e POSTGRES_PASSWORD=hauth -p 5432:5432 postgres:9.4

-   Run the example webserver in the same directory as the project.

        ~/.local/bin/hauth-server

-   Then make your requests with the client test tool.

        ~/.local/bin/hauth-client http://localhost:8443 123 supersekrat123
