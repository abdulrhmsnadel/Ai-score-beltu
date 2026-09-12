# AI-SCORE-BELTU CLI Quickstart

## Action shortcuts

- `-h` help
- `-v` version
- `-d` doctor
- `-e` list engines
- `-a TARGET` assessment
- `-t ENGINE TARGET` one engine test
- `-f` stored findings
- `-g` report from SQLite
- `-i ENGINE` engine requirements
- `-s TARGET` scope check
- `-m` latest Mailpit message

## Common option shortcuts

- `-w HOST` explicit allowed host (can repeat)
- `-H 'Name: value'` request header (can repeat)
- `-o FILE` JSON output
- `-D FILE` SQLite database
- `-r FILE` HTML report
- `-O ORIGIN` CORS test Origin
- `-k TOKEN` JWT token
- `-c URL` SSRF canary URL
- `-C HOST` SSRF canary allowlist
- `-A 'Header: value'` Access-Control Identity A / single session
- `-B 'Header: value'` Access-Control Identity B in comparison mode
- `-M MARKER` A-only Access-Control marker (repeatable)
- `-N MARKER` target-object marker in object-mutation mode
- `-P PARAM` object/resource query parameter
- `-V VALUE` alternate object/resource value
- `-p FILE_OR_URL` OpenAPI source

## PortSwigger lab pattern

Use the lab hostname as the explicit allowlist. Start by inspecting the engine, then test one engine at a time:

```bash
beltu -i cors
beltu -t cors 'https://YOUR-LAB.web-security-academy.net/account' -w YOUR-LAB.web-security-academy.net -O 'https://beltu.invalid'
```


Object-mutation example:

```bash
beltu -t access-control 'https://YOUR-LAB.web-security-academy.net/my-account?id=wiener' -w YOUR-LAB.web-security-academy.net -A $'Cookie: TEST_SESSION' -P id -V carlos -N carlos -x
```

For a conservative baseline:

```bash
beltu -a 'https://YOUR-LAB.web-security-academy.net/' -w YOUR-LAB.web-security-academy.net -o assessment.json -r assessment.html
```

Read stored results and generate a report later:

```bash
beltu -f --severity high
beltu -g -o report.json -r report.html
```
