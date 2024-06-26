## ✅ Known Bots
**Action:** Skip

This category lists known and legitimate bots, such as search engine crawlers from Google, Bing, and Yandex, as well as some specific user agents that are recognized as non-malicious. These bots are allowed to access the site without restriction.

```
(cf.client.bot) or 
(http.user_agent contains "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.175 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)") or 
(http.user_agent contains "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.1938.76 Safari/537.36") or 
(http.user_agent contains "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0") or 
(http.user_agent contains "AdGuard/4.5.17 (Linux; U; Android 14; SO-52C Build/65.2.B.2.152)")
```

## ⚠️ Sus Requests
**Action:** Block

This category targets potentially suspicious requests. It includes:
- Requests for specific file types and directories that are commonly targeted for attacks or are sensitive (e.g., `.aspx`, `.env`, `.git`, `.php`).
- Requests containing specific URI paths that might indicate probing for vulnerabilities or attempting to exploit known weaknesses (e.g., `/wp-json`, `/backup.zip`, `/sftp`).
- Requests with user agents or specific paths that indicate automated or non-browser access patterns commonly associated with malicious activity.

```
(http.request.uri.path contains ".aspx") or
(http.request.uri.path contains ".DS_Store") or
(http.request.uri.path contains ".env") or
(http.request.uri.path contains ".git") or
(http.request.uri.path contains ".idea") or
(http.request.uri.path contains ".kube") or
(http.request.uri.path contains ".php") or
(http.request.uri.path contains ".vs") or
(http.request.uri.path contains "//") or
(http.request.uri.path contains "/?rest_route=/wp/v2/users") or
(http.request.uri.path contains "/api/search?folderIds=0") or
(http.request.uri.path contains "/cms") or
(http.request.uri.path contains "/login.action") or
(http.request.uri.path contains "/readme") or
(http.request.uri.path contains "/readme.html") or
(http.request.uri.path contains "/readme.md") or
(http.request.uri.path contains "/side") or
(http.request.uri.path contains "/sito") or
(http.request.uri.path contains "/user.action") or
(http.request.uri.path contains "/wordpress") or
(http.request.uri.path contains "/wp") or
(http.request.uri.path contains "/wp-json") or
(http.request.uri.path contains "/wp1") or
(http.request.uri.path contains "/wp2") or
(http.request.uri.path contains "backup.zip") or
(http.request.uri.path contains "id_rsa") or
(http.request.uri.path contains "server.key") or
(http.request.uri.path contains "sftp") or
(http.request.uri.path contains "wordpress") or
(http.request.uri.path contains "wp-admin") or
(http.request.uri.path contains "wp-content") or
(http.request.uri.path contains "wp-includes") or
(http.request.uri.path eq "/config.json") or
(http.request.uri.path eq "/feed") or
(http.request.uri.path eq "/git") or
(http.request.uri.path eq "/ssh") or
(http.request.uri.path eq "/test") or
(http.request.uri.path eq "/web") or
(http.request.uri.path eq "/website") or
(lower(http.user_agent) contains "Apache-HttpClient") or
(lower(http.user_agent) contains "ipconfig") or
(lower(http.user_agent) contains "Knights%20of%20Degen") or
(lower(http.user_agent) contains "wlwmanifest") or
(lower(http.user_agent) contains "wp_is_mobile") or
(lower(http.user_agent) eq "")
```

## 🗑️ Sus Browsers
**Action:** Interactive Challenge

This category deals with suspicious or outdated browsers. It includes:
- User agents associated with older versions of browsers (e.g., old versions of Chrome, Firefox, and Android browsers).
- User agents that are often used by headless browsers or automated tools (e.g., `headlesschrome`, `dalvik`).
- User agents with specific patterns indicating non-standard browsing activity or potential for abuse.

For these requests, an interactive challenge (like CAPTCHA) is presented to verify that the requester is a legitimate user and not an automated system.

```
(lower(http.user_agent) contains "android 4") or
(lower(http.user_agent) contains "android 7" and http.user_agent ne "mozilla/5.0 (linux; android 7.0; sm-g930v build/nrd90m) applewebkit/537.36 (khtml, like gecko) chrome/59.0.3071.125 mobile safari/537.36 (compatible; google-read-aloud; +https://support.google.com/webmasters/answer/1061943)") or
(lower(http.user_agent) contains "android 8") or
(lower(http.user_agent) contains "android 9") or
(lower(http.user_agent) contains "chrome/103") or
(lower(http.user_agent) contains "chrome/106") or
(lower(http.user_agent) contains "chrome/107") or
(lower(http.user_agent) contains "chrome/117") or
(lower(http.user_agent) contains "chrome/119") or
(lower(http.user_agent) contains "chrome/17") or
(lower(http.user_agent) contains "chrome/33") or
(lower(http.user_agent) contains "chrome/34") or
(lower(http.user_agent) contains "chrome/35") or
(lower(http.user_agent) contains "chrome/36") or
(lower(http.user_agent) contains "chrome/37") or
(lower(http.user_agent) contains "chrome/41") or
(lower(http.user_agent) contains "chrome/44") or
(lower(http.user_agent) contains "chrome/49") or
(lower(http.user_agent) contains "chrome/52") or
(lower(http.user_agent) contains "chrome/58") or
(lower(http.user_agent) contains "chrome/60") or
(lower(http.user_agent) contains "chrome/64") or
(lower(http.user_agent) contains "chrome/65") or
(lower(http.user_agent) contains "chrome/69") or
(lower(http.user_agent) contains "chrome/70") or
(lower(http.user_agent) contains "chrome/74" and http.user_agent ne "Better Uptime Bot Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36") or
(lower(http.user_agent) contains "chrome/77") or
(lower(http.user_agent) contains "chrome/78") or
(lower(http.user_agent) contains "chrome/79") or
(lower(http.user_agent) contains "chrome/83") or
(lower(http.user_agent) contains "chrome/84") or
(lower(http.user_agent) contains "chrome/85") or
(lower(http.user_agent) contains "chrome/87") or
(lower(http.user_agent) contains "chrome/88") or
(lower(http.user_agent) contains "chrome/93") or
(lower(http.user_agent) contains "chrome/94") or
(lower(http.user_agent) contains "chrome/95") or
(lower(http.user_agent) contains "chrome/96") or
(lower(http.user_agent) contains "chrome/98") or
(lower(http.user_agent) contains "dalvik") or
(lower(http.user_agent) contains "edg/101") or
(lower(http.user_agent) contains "edg/96") or
(lower(http.user_agent) contains "embeddedbrowser") or
(lower(http.user_agent) contains "firefox/52") or
(lower(http.user_agent) contains "firefox/57") or
(lower(http.user_agent) contains "firefox/76") or
(lower(http.user_agent) contains "firefox/77") or
(lower(http.user_agent) contains "firefox/79") or
(lower(http.user_agent) contains "firefox/83") or
(lower(http.user_agent) contains "headlesschrome") or
(lower(http.user_agent) contains "html5plus") or
(lower(http.user_agent) contains "mozilla/5.0 (macintosh; intel mac os x 10_15_6)") or
(lower(http.user_agent) contains "mozilla/5.0 (macintosh; intel mac os x 10_9_2)") or
(lower(http.user_agent) contains "symbianos") or
(lower(http.user_agent) contains "ucbrowser") or
(lower(http.user_agent) contains "windows nt 6.1") or
(lower(http.user_agent) contains "wow64") or
(lower(http.user_agent) contains "yaapp_android") or
(lower(http.user_agent) eq "go-http-client/1.1")
```

## 🤖 Sus Bots
**Action:** Block

This category blocks bots known for scraping, spamming, or other malicious activities. It includes user agents for:
- Web crawlers and scrapers that are not authorized to access the site (e.g., `ahrefsbot`, `semrushbot`, `mj12bot`).
- Automated tools and bots used for data collection, security testing, and other purposes that could negatively impact the site's performance and security (e.g., `sqlmap`, `httrack`).

```
(lower(http.user_agent) contains "adbeat") or
(lower(http.user_agent) contains "admantx") or
(lower(http.user_agent) contains "ahrefsbot") or
(lower(http.user_agent) contains "appinsights") or
(lower(http.user_agent) contains "aspiegelbot") or
(lower(http.user_agent) contains "awariosmartbot") or
(lower(http.user_agent) contains "barkrowler") or
(lower(http.user_agent) contains "blexbot") or
(lower(http.user_agent) contains "bomborabot") or
(lower(http.user_agent) contains "buck") or
(lower(http.user_agent) contains "bvbot") or
(lower(http.user_agent) contains "bytespider") or
(lower(http.user_agent) contains "ccbot") or
(lower(http.user_agent) contains "censysinspect") or
(lower(http.user_agent) contains "checkhost") or
(lower(http.user_agent) contains "cincraw") or
(lower(http.user_agent) contains "claudebot") or
(lower(http.user_agent) contains "clickagy") or
(lower(http.user_agent) contains "cocolyzebot") or
(lower(http.user_agent) contains "criteobot") or
(lower(http.user_agent) contains "df bot 1.0") or
(lower(http.user_agent) contains "domainstatsbot") or
(lower(http.user_agent) contains "domcopbot") or
(lower(http.user_agent) contains "dotbot") or
(lower(http.user_agent) contains "embed.ly") or
(lower(http.user_agent) contains "friendlycrawler") or
(lower(http.user_agent) contains "grapeshotcrawler") or
(lower(http.user_agent) contains "gulperbot") or
(lower(http.user_agent) contains "httrack") or
(lower(http.user_agent) contains "ias_crawler") or
(lower(http.user_agent) contains "internet-structure-research-project-bot") or
(lower(http.user_agent) contains "keys-so-bot") or
(lower(http.user_agent) contains "linguee") or
(lower(http.user_agent) contains "linkfluence") or
(lower(http.user_agent) contains "magpie-crawler") or
(lower(http.user_agent) contains "mediatoolkitbot") or
(lower(http.user_agent) contains "megaindex") or
(lower(http.user_agent) contains "mj12bot") or
(lower(http.user_agent) contains "nimbostratus") or
(lower(http.user_agent) contains "omgili") or
(lower(http.user_agent) contains "onalyticabot") or
(lower(http.user_agent) contains "petalbot") or
(lower(http.user_agent) contains "proximic") or
(lower(http.user_agent) contains "pubmatic crawler bot") or
(lower(http.user_agent) contains "riddler") or
(lower(http.user_agent) contains "rogerbot") or
(lower(http.user_agent) contains "sbl-bot") or
(lower(http.user_agent) contains "seekport") or
(lower(http.user_agent) contains "semantic-visions") or
(lower(http.user_agent) contains "semanticbot") or
(lower(http.user_agent) contains "semrushbot") or
(lower(http.user_agent) contains "serpstatbot") or
(lower(http.user_agent) contains "sogou") or
(lower(http.user_agent) contains "sqlmap") or
(lower(http.user_agent) contains "traackr") or
(lower(http.user_agent) contains "trendictionbot") or
(lower(http.user_agent) contains "ttd-content") or
(lower(http.user_agent) contains "voluumdsp") or
(lower(http.user_agent) contains "wc-test-dev-bot") or
(lower(http.user_agent) contains "webtechbot") or
(lower(http.user_agent) contains "whatcms") or
(lower(http.user_agent) contains "zgrab")
```

## 💀 Dangerous Hosts
**Action:** Block

This category blocks access from IP addresses and Autonomous System Numbers (ASNs) known for malicious activities. It includes:
- Specific IP addresses that have been flagged for abusive behavior or security risks.
- ASNs associated with high volumes of spam, attacks, or other unwanted activities (e.g., ASNs for known data centers used by attackers).

These rules help to protect the website by preventing access from sources that are likely to be involved in malicious activities.

```
(ip.geoip.asnum eq 200651) or
(ip.geoip.asnum eq 2027) or
(ip.geoip.asnum eq 203953) or
(ip.geoip.asnum eq 205100) or
(ip.geoip.asnum eq 208323) or
(ip.geoip.asnum eq 210630) or
(ip.geoip.asnum eq 37963) or
(ip.geoip.asnum eq 399486) or
(ip.geoip.asnum eq 53667) or
(ip.geoip.asnum eq 55960) or
(ip.src eq 102.22.20.58) or
(ip.src eq 103.151.30.155) or
(ip.src eq 103.153.134.22) or
(ip.src eq 103.171.156.218) or
(ip.src eq 103.177.9.104) or
(ip.src eq 103.188.252.66) or
(ip.src eq 103.250.130.104) or
(ip.src eq 103.46.4.7) or
(ip.src eq 103.68.214.97) or
(ip.src eq 104.196.252.127) or
(ip.src eq 109.202.99.46) or
(ip.src eq 114.129.2.82) or
(ip.src eq 114.132.202.246) or
(ip.src eq 114.132.202.78) or
(ip.src eq 115.127.116.242) or
(ip.src eq 12.127.44.138) or
(ip.src eq 122.155.165.191) or
(ip.src eq 132.147.137.52) or
(ip.src eq 138.121.161.84) or
(ip.src eq 143.255.80.134) or
(ip.src eq 148.230.206.229) or
(ip.src eq 152.32.213.18) or
(ip.src eq 161.49.215.28) or
(ip.src eq 165.16.88.161) or
(ip.src eq 168.232.174.43) or
(ip.src eq 172.183.241.1) or
(ip.src eq 175.22.148.13) or
(ip.src eq 177.130.104.106) or
(ip.src eq 177.234.240.123) or
(ip.src eq 177.70.72.103) or
(ip.src eq 177.87.144.122) or
(ip.src eq 179.1.192.5) or
(ip.src eq 179.43.188.122) or
(ip.src eq 179.49.162.133) or
(ip.src eq 180.211.183.2) or
(ip.src eq 184.82.244.173) or
(ip.src eq 185.255.45.241) or
(ip.src eq 187.188.101.205) or
(ip.src eq 187.204.18.213) or
(ip.src eq 188.136.154.43) or
(ip.src eq 189.35.11.247) or
(ip.src eq 189.48.88.204) or
(ip.src eq 190.83.12.220) or
(ip.src eq 190.94.212.198) or
(ip.src eq 190.94.212.240) or
(ip.src eq 191.240.153.144) or
(ip.src eq 191.37.1.155) or
(ip.src eq 194.126.177.84) or
(ip.src eq 199.167.236.12) or
(ip.src eq 200.174.198.136) or
(ip.src eq 200.174.198.222) or
(ip.src eq 200.174.198.224) or
(ip.src eq 200.174.198.92) or
(ip.src eq 201.131.239.233) or
(ip.src eq 201.77.128.158) or
(ip.src eq 202.47.181.150) or
(ip.src eq 202.62.84.210) or
(ip.src eq 209.209.28.22) or
(ip.src eq 212.174.79.169) or
(ip.src eq 213.232.87.230) or
(ip.src eq 213.232.87.232) or
(ip.src eq 213.232.87.234) or
(ip.src eq 216.87.69.230) or
(ip.src eq 217.182.194.108) or
(ip.src eq 24.172.34.114) or
(ip.src eq 34.105.123.106) or
(ip.src eq 34.105.60.137) or
(ip.src eq 34.83.15.88) or
(ip.src eq 34.83.51.218) or
(ip.src eq 34.92.250.88) or
(ip.src eq 36.182.49.26) or
(ip.src eq 36.255.84.69) or
(ip.src eq 36.91.135.141) or
(ip.src eq 36.95.142.35) or
(ip.src eq 4.227.97.45) or
(ip.src eq 43.134.1.40) or
(ip.src eq 43.134.121.40) or
(ip.src eq 43.153.207.93) or
(ip.src eq 45.164.174.27) or
(ip.src eq 45.236.170.234) or
(ip.src eq 45.70.236.150) or
(ip.src eq 46.161.196.222) or
(ip.src eq 46.2.5.84) or
(ip.src eq 47.106.193.183) or
(ip.src eq 51.145.176.250) or
(ip.src eq 52.169.23.0) or
(ip.src eq 52.178.159.39) or
(ip.src eq 59.152.14.109) or
(ip.src eq 59.152.14.111) or
(ip.src eq 61.129.2.212) or
(ip.src eq 62.33.53.248) or
(ip.src eq 84.51.15.250) or
(ip.src eq 85.94.24.29) or
(ip.src eq 88.87.78.95) or
(ip.src eq 91.215.85.29) or
(ip.src eq 94.179.141.78)
```
