# pritunl-api-client

# Setup

Requirements:
1. [Anaconda][anaconda] in your path. Preferably with the `conda-init` setup in your `.bashrc` or `.zshrc`.
2. From this directory:
```shell
conda config --set env_prompt '({name}) '
cd <PATH TO THIS PROJECT>
conda create -y --p $(pwd)/conda-env
conda activate $(pwd)/conda-env
conda env update --file conda-environment.yml
```

Highley suggested to also have `jq` installed as output exclusively in JSON.

# Usage

**Get Pritunl status**
```shell script
./pritunl-api-client.py --url <pritunl-host> --token <pritunl-api-token> --secret <pritunl-api-secret> get-status
```

**Find user by Ip Address (using jq)**
```shell script
./pritunl-api-client.py \
  -u <pritunl-host> \
  -t <pritunl-api-token> \
  -s <pritunl-api-secret> 
  get-user -o 'BAZBAZ' \ 
  | jq '.[] | select(.status) | select(.servers[].virt_address == "172.30.0.31")'
```

*Result:*
```json
{
  "auth_type": "google",
  "dns_servers": null,
  "pin": false,
  "dns_suffix": null,
  "servers": [
    {
      "status": true,
      "platform": "mac",
      "server_id": "FOOFOO",
      "virt_address6": "fd00:ac1e::172:30:0:31",
      "virt_address": "172.30.0.31",
      "name": "terradatum",
      "real_address": "123.123.123.123",
      "connected_since": 1586467079,
      "id": "BARBAR",
      "device_name": "ancient-meadow-6678"
    }
  ],
  "disabled": false,
  "network_links": [],
  "port_forwarding": null,
  "id": "BLAHBLAH",
  "organization_name": "Terradatum",
  "type": "client",
  "email": "foo@bar.com",
  "status": true,
  "dns_mapping": null,
  "otp_secret": "HALBHALB",
  "client_to_client": false,
  "yubico_id": null,
  "sso": "google",
  "bypass_secondary": false,
  "groups": [],
  "audit": false,
  "name": "foo@bar.com",
  "gravatar": true,
  "otp_auth": false,
  "organization": "BAZBAZ"
}

```

[anaconda]: https://www.anaconda.com/distribution/
