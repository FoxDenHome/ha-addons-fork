{{/*
    Options saved in the addon UI are available in .options
    Some variables are available in .variables, these are added in nginx/run
*/}}
include /etc/nginx/modules/*.conf;

error_log stderr;
pid /var/run/nginx.pid;

worker_processes auto;

events {
    worker_connections 1024;
}

http {
    map_hash_bucket_size 128;

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }

    server_tokens off;

    server_names_hash_bucket_size 128;

    # intermediate configuration
    # https://ssl-config.mozilla.org/#server=nginx&version=1.28.0&config=intermediate&openssl=3.5.0
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;

    {{- if .options.cloudflare }}
    include /data/cloudflare.conf;
    {{- end }}

    {{- if .options.real_ip_from }}
    {{- range .options.real_ip_from }}
    set_real_ip_from {{.}};
    {{- end }}
    real_ip_header proxy_protocol;
    {{- end }}

    include /etc/nginx/resolver.conf;
    js_path "/etc/nginx/js/";
    js_fetch_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
    js_var $njs_acme_server_names "{{ .options.domain }}";
    js_var $njs_acme_account_email "{{ .options.email }}";
    js_var $njs_acme_dir "/ssl/acme";
    js_var $njs_acme_directory_uri "https://acme-v02.api.letsencrypt.org/directory";
    js_shared_dict_zone zone=acme:1m;
    js_import acme from acme.js;

    server {
        server_name _;
        listen 80 default_server;
        listen 443 ssl default_server;
        listen [::]:80 default_server;
        listen [::]:443 ssl default_server;

        {{- if .options.real_ip_from }}
        listen 81 default_server proxy_protocol;
        listen [::]:81 default_server proxy_protocol;
        listen 444 ssl default_server proxy_protocol;
        listen [::]:444 ssl default_server proxy_protocol;
        {{- end }}

        http2 on;
        ssl_reject_handshake on;
        return 444;
    }

    server {
        server_name {{ .options.domain }};

        location = /readyz {
            add_header Content-Type text/plain always;
            return 200 "OK";
        }

        location @acmePeriodicAuto {
          js_periodic acme.clientAutoMode interval=1m;
        }

        location /.well-known/acme-challenge/ {
          js_content acme.challengeResponse;
        }

        # These shouldn't need to be changed
        listen 80;
        listen [::]:80;
        {{- if .options.real_ip_from }}
        listen 81 proxy_protocol;
        listen [::]:81 proxy_protocol;
        {{- end }}
        location / {
            return 301 https://$host$request_uri;
        }
    }

    server {
        server_name {{ .options.domain }};

        ssl_session_timeout 1d;
        ssl_session_cache shared:MozSSL:10m;
        ssl_session_tickets off;

        js_set $dynamic_ssl_cert acme.js_cert;
        js_set $dynamic_ssl_key acme.js_key;
        ssl_certificate data:$dynamic_ssl_cert;
        ssl_certificate_key data:$dynamic_ssl_key;

        # dhparams file
        ssl_dhparam /data/dhparams.pem;

        {{- if not .options.real_ip_from  }}
        listen 443 ssl;
        listen [::]:443 ssl;
        http2 on;
        {{- else }}
        listen 443 ssl;
        listen [::]:443 ssl;
        listen 444 ssl proxy_protocol;
        listen [::]:444 ssl proxy_protocol;
        http2 on;
        {{- range .options.real_ip_from }}
        set_real_ip_from {{.}};
        {{- end  }}
        real_ip_header proxy_protocol;
        {{- end }}

        {{- if .options.hsts }}
        add_header Strict-Transport-Security "{{ .options.hsts }}" always;
        {{- end }}

        proxy_buffering off;
        proxy_request_buffering off;
        proxy_headers_hash_max_size 512;
        proxy_headers_hash_bucket_size 128;

        {{- if .options.customize.active }}
        include /share/{{ .options.customize.default }};
        {{- end }}

        location = /readyz {
            add_header Content-Type text/plain always;
            return 200 "OK";
        }

        location /.well-known/acme-challenge/ {
          js_content acme.challengeResponse;
        }

        location / {
            proxy_pass http://homeassistant.local.hass.io:{{ .variables.port }};
            proxy_set_header Origin $http_origin;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Host $http_host;
            proxy_redirect http:// https://;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header X-Forwarded-Host $http_host;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }

    {{- if .options.customize.active }}
    include /share/{{ .options.customize.servers }};
    {{- end }}
}
