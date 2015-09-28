<div id="table-of-contents">
<h2>Table of Contents</h2>
<div id="text-table-of-contents">
<ul>
<li><a href="#orgheadline1">1. Build (with example main)</a></li>
<li><a href="#orgheadline2">2. External Requirements</a></li>
<li><a href="#orgheadline3">3. Run</a></li>
</ul>
</div>
</div>


# Build (with example main)<a id="orgheadline1"></a>

    stack install . --flag hauth:example

# External Requirements<a id="orgheadline2"></a>

-   Consul
    
    The example uses default port 8500 on localhost. The easiest way
    to start this is using a docker instance.
    
        docker run -i -t -p 8500:8500 -h consul progrium/consul -server -bootstrap -ui-dir /ui
    
    Then use the handy [consul cli](https://github.com/CiscoCloud/consul-cli) tool & write a kv pair to consul.
    The data about the partner name & their hmac secret goes into
    consul.  The code watches for updates from Consul.
    
        consul-cli kv-write 123 "{\"secret\":\"supersekrat123\",\"name\":\"test\"}"

-   Postgres 
    
    The example-hauth Main.hs has postgres on localhost with
    user/name/password/db all set to 'hauth'.
    
    Persisent migrates the schema for you, of course.

# Run<a id="orgheadline3"></a>

-   Run the example webserver in the same directory as the project.
    
        ~/.local/bin/example-hauth
    
    -   Then make your requests for a static file in the same directory
        as the project.
        
            curl -H "Authorization: MAC \
            id=123 \
            ts=1443482988 \
            nonce=763d5941-662e-11e5-9e67-0235b842756b \
            mac=53bb57e3d8e1306b5725de2e72382f1c1b0ae91dfa136958607fa5ab27bc889b \
            " http://localhost:4321/hauth.cabal
