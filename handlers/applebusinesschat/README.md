
```ini
location ~ /handlers/facebook/ {
    rewrite /handlers/facebook/(.*) /c/fb/$1/receive;
    proxy_set_header Host $http_host;
    proxy_pass http://courier_server;
    break;
  }
```