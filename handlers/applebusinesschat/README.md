
## Rapidpro config

```ini
# NGINX handler rewrite for old systems
location ~ /handlers/applebusinesschat/ {
    rewrite /handlers/applebusinesschat/(.*) /c/ac/$1/receive;
    proxy_set_header Host $http_host;
    proxy_pass http://courier_server;
    break;
  }
```

- Create a new Channel `AC` in RapidPro for the config settings
```bash
business_id # apple business id
csp_id # Apple CSP ID
secret # Apple Secret Key

```