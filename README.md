
<img src="./s3.png" alt="drawing" width="200"/>

# Openbridge SFTP S3 Transfer Gateway
This is a Secure File Transfer Protocol (`SFTP`) service for the transfer of data to AWS S3. The SFTP S3 Transfer Gateway supports basic file transfers as well as creating data pipelines that allow you to deliver, process and route data sources to a target warehouse system like Amazon Redshift, Amazon Redshift Spectrum, Amazon Athena or even Google BigQuery. Consolidating your data to a warehouse allows you to easily use your favorite analytics tools like Tableau, QlikView, Mode or Looker.

SFTP is based on the `SSH2` protocol, which encodes activity over a secure channel. Unlike `FTP`, `SSH2`  uses a single TCP connection and sends multiple transfers, or "channels", over that single connection. Use of SSH allows the Openbridge SFTP S3 Transfer Gateway to been setup in HA configurations via HaProxy or AWS ELB.


# Use Cases

What are some use cases for Openbridge SFTP S3 Transfer Gateway?

* File sharing between teams
* Perfect for automated exports from internal systems like an ERP, ETL, MySQL, SQL Server, Oracle or other enterprise systems
* Process exports from 3rd party systems like Salesforce (see [How to export data from ExactTarget](https://blog.openbridge.com/export-tracking-data-from-salesforce-marketing-cloud-8a0a4c1f37dc) and Adobe Analytics ([see How to export data from Adobe Analytics](https://docs.openbridge.com/data-pipelines/setting-up-adobe-clickstream-feeds)).
* Supports secure file transfer protocol with a variety of SFTP client. The SFTP protocol is secure and commonly use for transferring files via command line or graphical interfaces.
* Lastly, support use cases where you have an ad hoc CSV file (e.g., sales reports, media plans, lookup files or any other CSV file) that you want to get loaded into your data warehouse.

# Features

The core modules being used in install are as follows;

- SFTP support
- SSL/TLS support
- SCP support
- SQL support
- Fixed IP for external partner/IT whitelisting
- Quota support
- Dynamic blacklist support
- Traffic shaping support
- TCP wrappers support
- Monitoring
- High availability support
- Transaction Logging
- User/Password and Public Key Authentication
- MySQL (MariaDB) backend
- Amazon S3 filesystem
- Customized User Directories
- Throttled transfers
- Strong encryption
- Large file support
- Drag and drop support
- Activity notifications via Slack

# Getting Started

## Prerequisites
 * **Docker**: You will need to make sure Docker is installed on your host.
 * **MariaDB**: This is where your users, keys, logs, quotas.. are stored. You can run this locally, use Amazon RDS or an existing install within your infrastructure.


## Step 1: Building
The first step is to build or pull an image. To build an image, simply run the Docker build command:
```bash
docker build -t openbridge/ob_proftpd .
```
Using Docker Hub:
```bash
docker pull openbridge/ob_proftpd
```

## Step 2: Setting Up Your Environment

There are a few options when running on AWS. If you are using an IAM Role, then you can forgo the need for a key and secret. This is likely the primary use case for those deploying to AWS.

```bash
MODE=
CRONFILE=
MOUNT_POINT=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=
AWS_IAMROLE=
AWS_S3BUCKET=
MYSQL_HOST=
MYSQL_READHOST=
APP_DATABASE=
APP_PORT=
APP_SYSTEM_USER=
APP_SYSTEM_PASSWORD=
APP_TEST_USER=
APP_TEST_PASSWORD=
APP_VERSION=
CLAMD_STATUS=off
CLAMD_HOST=
MEMCACHE_STATUS=off
MEMCACHE_HOST=
```


### 1. Mode
If you are deploying to AWS, then you should set `MODE` to `aws`:
```bash
MODE=aws
```
However, if you are running this locally or another could service, say for development or testing, then you should set `MODE` to something that makes sense for you:
```bash
MODE=oracle
```
If you do not set `MODE`, it will use a default of `dev`.

**NOTE**: Please note that when running in non AWS settings (`MODE=oracle`), the server still **requires a connection to AWS S3**. The reason for this dependency is that the underlying filesystem is based on S3 so without that testing and development becomes difficult. So can run this anywhere, you will still need to set your S3 connection details (see #4)


### 2. IP Address

There is a local IP and a public IP for a container. The address of your instance is determined automatically based on the context of your `MODE`.

* Using non AWS mode will get the primary route for your Docker service. For example: `route -n | awk '$2 ~/[1-9]+/ {print $2;}'`
* Using `MODE=aws` will check AWS for the IP. For example: `curl http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null`

If running on `aws`, it will use:
```bash
PUBLICIPV4="$(curl http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)"
LOCALIPV4="$(curl http://169.254.169.254/latest/meta-data/local-ipv4 2>/dev/null)"
```

```bash
PUBLICIPV4=$(route -n | awk '$2 ~/[1-9]+/ {print $2;}')
LOCALIPV4=$(route -n | awk '$2 ~/[1-9]+/ {print $2;}')
```
You can check `/docker-entrypoint.sh` for more details on the setup process.

### 3. Cron File
If you want to persist your container you can set it up to always be running with crond as a background process. While most everything is automated there are a few configuration items you need to set.

```bash
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CACHE_PREFIX={{CACHE_PREFIX}}
AWS_ACCESS_KEY_ID={{AWS_ACCESS_KEY_ID}}
AWS_SECRET_ACCESS_KEY={{AWS_SECRET_ACCESS_KEY}}
AWS_S3BUCKET={{AWS_S3BUCKET}}
*/5 * * * * /usr/bin/env bash -c /tests/test_mount.sh 2>&1
*/5 * * * * /usr/bin/env bash -c /tests/test_proftpd.sh 2>&1
59 1 * * * /usr/bin/env bash -c /tests/test_cache.sh 1000000000 --silent
*/5 * * * * /usr/bin/env bash -c /tests/test_mysql.sh 2>&1
*/45 * * * * /usr/bin/env bash -c /usr/bin/ban 2>&1
*/30 * * * * /usr/bin/env bash -c /usr/bin/verify 2>&1
*/5 * * * * /usr/bin/env bash -c /usr/bin/pubkeysync 2>&1
```

There is a sample of this in `cron/crontab.conf`. You can use this as a starting point for your own config. Once you have your config ready, we can move to Step 2.

#### Mount your `crontab.conf` config
Next, you will want to mount your config file. The config is on your host, not in the container. To get it into your container you need to mount it from your host into the container.

The basic template is this:

```docker
-v /path/to/the/file/on/your/host/crontab.conf:/where/we/mount/in/container/crontab.conf
```

This example shows the mount your config in docker compose format:
```docker
volumes:
  - /Github/local-path/cron/crontab.conf:/crontab.conf
```
It will look the same if you are doing it via Docker run:
```docker
-v /Github/local-path/cron/crontab.conf:/crontab.conf
```
In those examples, the `crontab.conf` located in my local GitHub folder will get mounted inside the container at `/crontab.conf`

Mounting your config makes it available to the startup service within your container. If you are unfamiliar with `-v` or `volumes`, check the docs from Docker.


### 4. Mount Point For S3
The default mount location for a container is `/mnt`. We suggest **NOT** changing this behavior unless you know what you are doing.
```
MOUNT_POINT=/mnt
```

#### AWS S3 Information
There a couple of different paths to mount your S3 location. One path requires that you are running the service on AWS. The other path can work locally or on AWS.

##### AWS Only: Using IAM Roles
```
AWS_DEFAULT_REGION=us-east-1
AWS_IAMROLE=my-role
AWS_S3BUCKET=my-sftp-test
```

##### AWS or Local: Using KEY and Secret
An alternate approach, one you need to use for local development, is the use of the key and secret:

```
AWS_ACCESS_KEY_ID=XXXXXXXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXX
AWS_DEFAULT_REGION=us-east-1
AWS_S3BUCKET=my-sftp-test
```
In all cases, you need to set your S3 bucket name and region.

### 5. MariaDB (MySQL)
The service supports using a read replica, hence the `MYSQL_READHOST` variable. However, if you are not using a read replica simply copy the IP or hostname into both locations. This is an example:
```bash
MYSQL_HOST=172.17.0.1
MYSQL_READHOST=172.17.0.1
```

The system assumes the default `3306` port is used. If you are using a different port, included it in the variables. This is an example:

```bash
MYSQL_HOST=172.17.0.1:3308
MYSQL_READHOST=172.17.0.1:3308
```
If you are using a remote/external MySQL instance, make sure it can be reached by the container. This usually will require firewall access for the instance/host running the container. Also, please see the section on setting up user accounts for the service below.

### 6. SFTP Server System Settings
There are a few settings you need to configure for the S3 SFTP Gateway. The first is the database name. The default name is `ftpd`:

```bash
APP_DATABASE=ftpd
```
Next, you need to set up a user that is authorized to connect to the database:
```bash
APP_SYSTEM_USER=foobar
APP_SYSTEM_PASSWORD=changeme
```

```bash
APP_TEST_USER=tester
APP_TEST_PASSWORD=changeme
```
This references your configuration directory. For example, let us say you have a local configuration on your host located here: `/path/to/config/v2`.
You should set your `APP_VERSION` to your config. In this case `v2`:
```bash
APP_VERSION=v2
```
Lastly, you will want to make sure your config is mounted **IN** the container at runtime. Make sure your local path is mounted to `/etc/proftpd`
inside the container.
```bash
-v /path/to/config:/etc/proftpd
```
If you ran a build and included the config within the build, there is no need to do the volume mount. Simply set the `APP_VERSION` to whatever your config is.

### 7. Optional Settings
See below for virus and malware scanning options.

By default these are off. Memcache **only** applies to FTPES, which is used to cache TLS sessions. Clam AV can be resource intensive, so make sure it the environment you run it in is sized correctly.

While these services are supported they require external services to be configured, deployed and managed.  They are **not** included in this project.

```bash
CLAMD_STATUS=off
CLAMD_HOST=
MEMCACHE_STATUS=off
MEMCACHE_HOST=
```

# Setup And Configure User Accounts In Database
Openbridge currently supports public key and password authentication for both SFTP and SCP file transfer protocols. The server does not support any shell access. Also, not all SFTP commands are accepted.

Users are created and stored outside of the Openbridge application. Openbridge uses MariaDB (MySQL) to store user account information. This ensures each Openbridge container can scale horizontally. Spin up 30 Openbridge container, each will connect securely to a backend database for authorizations, whitelists, blacklists, quotas and logs.

## Step 1: Creating Accounts

In this example we will have a user called `peter`. Peter needs a password! How did you generate a password? You can create a random password string like this `openssl rand -hex 16 | tr -d '\n'`. This will result in a `USER_PASSWORD` like:
```bash
USER_PASSWORD="00cd555ee93dec9c999a0622b00e890e"
```
## Step 2: Generate Your Salt

In addition to user and password, we need to create a **salt**. Salts are used to safeguard passwords in the database. Historically a password was stored in plaintext on a system, but over time additional safeguards developed to protect a user's password against being read from the system. A salt is one of those methods.

The salt uses a cryptographic hash function, and the resulting output (but not the original password) is stored with the salt in a database. Hashing allows for later authentication without keeping and therefore risking the plaintext password in the event that the authentication data store is compromised.


We generate the salt like we do the password: `openssl rand -hex 32 | tr -d '\n'`. This gave us our `USER_SALT`:

```bash
USER_SALT="245f772c6e7eda0a3d09ab4a2ee55eb4a31e97c2df2fa8da0a7cf8baf2d45db"
```

## Step 3: Hashing Your Password
You need to hash your password in the database. The process is simple enough and here is an example.

First, you need to take your password `00cdCCCee93dec9c549a06b5000e890e` and salt `245f772c6e7eda0a3d99ab4a2eeVVeb4a31e97c2df2fa8da0a7cf8baf2d45db`  to generate hashed password. Here is the an example CLI using openssl:

```bash
printf "%s" "{{USER_SALT}}{{USER_PASSWORD}}" | openssl dgst -sha256 | tr -d '\n'
```
Inputing the values into the CLI will look something like this:
```bash
printf "%s" "245f772c6e7eda0a3d09ab4a2ee55eb4a31e97c2df2fa8da0a7cf8baf2d45db00cd555ee93dec9c549a06b5000e890e" | openssl dgst -sha256 | tr -d '\n'
```

This would create a hashed password for us to use:
```bash
564f573debf1920535b5d7cb686a474b5cbe98819fbd98e34478c3070e4948f7
```
Lastly, you can then insert this into the `ftpd_user` table for the user this password applies:
```sql
INSERT IGNORE INTO ftpd_user (id, userid, passwd, subscriptionid, uid, gid, homedir, status, shell, count, accessed, modified) VALUES ('', 'peter', '564f573debf1920535b5d7cb686a474b5cbe98819fbd98e34478c3070e4948f7','test001', 2001, 2001, '/tmp/tester', 'active', '/sbin/nologin', 0, '', '');
```
Lastly, you will need to update the `ftpd_salt` table with your userid and salt value

```sql
INSERT INTO ftpd_salt (userid,salt) VALUES ('peter','245f772c6e7eda0a3d09ab4a2ee55eb4a31e97c2df2fa8da0a7cf8baf2d45db') ON DUPLICATE KEY UPDATE salt='245f772c6e7eda0a3d09ab4a2ee55eb4a31e97c2df2fa8da0a7cf8baf2d45db';
```

## Step 4: Public Key
SSH2 uses public keys for authentication and message protection. The very popular OpenSSH server uses a particular file format for storing public keys in files. However, that format is not portable; it uses a format very specific to OpenSSH. To ensure portable keys, we leverage the [RFC4716](http://www.faqs.org/rfcs/rfc4716.html) format for public keys.

**The RFC4716 format is required**. If you do not use this format, it is unlikely to work. This means that if you wish to use your public keys with the you will need to convert them from to the [RFC4716](http://www.faqs.org/rfcs/rfc4716.html) format. Fortunately, this is supported by OpenSSH's ssh-keygen utility, e.g.:

```bash
sudo ssh-keygen -e -f /path/to/your/key.pub
```

This will generate a RFC key which you would then create a record for in the `ftpd_userkey` table;

```sql
INSERT INTO ftpd_userkey (userid,publickey) VALUES ('peter','---- BEGIN SSH2 PUBLIC KEY ----
Comment: "2048-bit RSA, converted by root@dude-MacBook-Pro.local fr"
AAAAB3NzaC1yc2EAAAADAQABAAABAQC+4ejAXI7PEa1i9J50LRQMOlHtEQ0+nRK91uBH77
gmZR5OxuaI092ErqspYpOa4DkOPxaoU5qYUxiUbbkKwtutCgTHXuS5Wt8IZMVtKsuMGZ3j
gUkNWcSLfyRnXK0XejNnMCSdOuauyHzD8ogRyDHznzS4kt+Ikaxr0n5rZ9e+zES5vOFML6
SeI3zq9ROHOjxNx4cbmbMJo7aG93xPsKG3kmtI7UndbQf+/Q68qPVoLqJJh5HRDt7CExHQ
2BAStaDpy2alMhZ1b+Ie9HRTDdZtixDrmkBsc09+cqyAATkKx5nTaHCw81SDAihGkAr309
QXxJvRWo7TeRfZMnZR1eqp
---- END SSH2 PUBLIC KEY ----');
```


# Logging



## Event Logs
The service defaults to output extend logs to SYSLOG. This is to facilitate dispatching logs to Cloudwatch. Please note that while this **enables** the ability to send to Cloudwatch, you still need to configure your container to do so. You can check out the docs here: https://docs.docker.com/config/containers/logging/awslogs/


```bash
Jan 21 23:27:50 ede0c5892520 local0.info proftpd[472]: {"time":"2019-01-21 23:27:50,677","cmd":"CHANNEL_OPEN","full_path":"-","remote_user":"tester","remote_dns":"172.24.0.1","remote_ip":"172.24.0.2","local_ip":"172.24.0.2","local_dns":"172.24.0.2","protocol":"ssh2","transfe
Jan 21 23:27:50 ede0c5892520 local0.info proftpd[472]: {"time":"2019-01-21 23:27:50,679","cmd":"CHANNEL_REQUEST","full_path":"-","remote_user":"tester","remote_dns":"172.24.0.1","remote_ip":"172.24.0.2","local_ip":"172.24.0.2","local_dns":"172.24.0.2","protocol":"sftp","tran
Jan 21 23:27:50 ede0c5892520 local0.info proftpd[472]: {"time":"2019-01-21 23:27:50,679","cmd":"INIT","full_path":"-","remote_user":"tester","remote_dns":"172.24.0.1","remote_ip":"172.24.0.2","local_ip":"172.24.0.2","local_dns":"172.24.0.2","protocol":"sftp","transfer_time":
Jan 21 23:27:50 ede0c5892520 local0.info proftpd[472]: {"time":"2019-01-21 23:27:50,681","cmd":"REALPATH","full_path":"-","remote_user":"tester","remote_dns":"172.24.0.1","remote_ip":"172.24.0.2","local_ip":"172.24.0.2","local_dns":"172.24.0.2","protocol":"sftp","transfer_ti
Jan 21 23:27:50 ede0c5892520 local0.info proftpd[472]: {"time":"2019-01-21 23:27:50,698","cmd":"OPENDIR","full_path":"-","remote_user":"tester","remote_dns":"172.24.0.1","remote_ip":"172.24.0.2","local_ip":"172.24.0.2","local_dns":"172.24.0.2","protocol":"sftp","transfer_tim
Jan 21 23:27:50 ede0c5892520 local0.info proftpd[472]: {"time":"2019-01-21 23:27:50,852","cmd":"READDIR","full_path":"-","remote_user":"tester","remote_dns":"172.24.0.1","remote_ip":"172.24.0.2","local_ip":"172.24.0.2","local_dns":"172.24.0.2","protocol":"sftp","transfer_tim
Jan 21 23:27:50 ede0c5892520 local0.info proftpd[472]: {"time":"2019-01-21 23:27:50,858","cmd":"READDIR","full_path":"-","remote_user":"tester","remote_dns":"172.24.0.1","remote_ip":"172.24.0.2","local_ip":"172.24.0.2","local_dns":"172.24.0.2","protocol":"sftp","transfer_tim
Jan 21 23:27:50 ede0c5892520 local0.info proftpd[472]: {"time":"2019-01-21 23:27:50,859","cmd":"MLSD","full_path":"/mnt/ebs/ftpd/tester/","remote_user":"tester","remote_dns":"172.24.0.1","remote_ip":"172.24.0.2","local_ip":"172.24.0.2","local_dns":"172.24.0.2","protocol":"sf
Jan 21 23:27:50 ede0c5892520 local0.info proftpd[472]: {"time":"2019-01-21 23:27:50,859","cmd":"CLOSE","full_path":"-","remote_user":"tester","remote_dns":"172.24.0.1","remote_ip":"172.24.0.2","local_ip":"172.24.0.2","local_dns":"172.24.0.2","protocol":"sftp","transfer_time"
```

## Transaction Log To Database

The `ftpd_log` captures all the file transfer transactions that occur in the system. This is the primary log for events that are transacting at the SFTP application level. In an effort to minimize signal to noise in the logs, the following commands are logged: `ABOR`,`DELE`,`ERR_STOR`,`STOR` and `STOU`
```sql
CREATE TABLE IF NOT EXISTS `ftpd_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT DEFAULT NULL,
  `userid` VARCHAR(50) NOT NULL,
  `server_ip` VARCHAR(64) NOT NULL,
  `transfer_date` DATETIME NOT NULL,
  `operation` VARCHAR(1024) NOT NULL DEFAULT '',
  `protocol` VARCHAR(6) NOT NULL DEFAULT '',
  `client_ip` VARCHAR(64) NOT NULL DEFAULT '',
  `transfer_time` FLOAT(16) unsigned NOT NULL DEFAULT '0',
  `bytes_transfer` BIGINT(20) unsigned NOT NULL DEFAULT '0',
  `path_hash` VARCHAR(512) NOT NULL,
  `file_hash_type` VARCHAR(6) NOT NULL DEFAULT '',
  `file_hash` VARCHAR(512) NOT NULL,
  `bucket` VARCHAR(255) NOT NULL DEFAULT '',
  `file_path` VARCHAR(1024) NOT NULL DEFAULT '',
  `transfer_status` VARCHAR(12) NOT NULL DEFAULT '',
  `process_status` TINYINT(1)NOT NULL DEFAULT '0',
  `modified` TIMESTAMP NOT NULL DEFAULT NOW(),
  `accessed` TIMESTAMP NOT NULL DEFAULT NOW() ON UPDATE now(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='ProFTP access log table';
```

```bash
+----+--------+------------+---------------------+--------------------------+----------+------------+---------------+----------------+----------------------------------+----------------+-----------+--------------+-----------------------------------------+-----------------+----------------+---------------------+---------------------+
| id | userid | server_ip  | transfer_date       | operation                | protocol | client_ip  | transfer_time | bytes_transfer | path_hash                        | file_hash_type | file_hash | bucket       | file_path                               | transfer_status | process_status | modified            | accessed            |
+----+--------+------------+---------------------+--------------------------+----------+------------+---------------+----------------+----------------------------------+----------------+-----------+--------------+-----------------------------------------+-----------------+----------------+---------------------+---------------------+
|  1 | tester | 172.24.0.1 | 2019-01-09 01:01:15 | STOR /summary.xls        | sftp     | 172.24.0.2 |             0 | -              | 687071838d02524f28e3ee8a63646b3f |                |           | s3sftp-test | /mnt/ebs/ftpd/tester/summary.xls        | failed          |              6 | 2019-01-09 01:01:15 | 2019-01-09 01:30:01 |
|  2 | tester | 172.24.0.1 | 2019-01-09 01:01:16 | STOR /summary.xls        | sftp     | 172.24.0.2 |             0 | -              | 687071838d02524f28e3ee8a63646b3f |                |           | s3sftp-test | /mnt/ebs/ftpd/tester/summary.xls        | failed          |              6 | 2019-01-09 01:01:16 | 2019-01-09 01:30:01 |
|  3 | tester | 172.24.0.1 | 2019-01-09 01:05:59 | STOR /select-s3.png      | sftp     | 172.24.0.2 |         1.002 | 79995          | e18fb25ed6434279ae96a879bada9d60 |                |           | s3sftp-test | /mnt/ebs/ftpd/tester/select-s3.png      | success         |              5 | 2019-01-09 01:05:59 | 2019-01-09 01:30:01
```

## Audit & Verification Log

While `ftpd_log` captures overall transactions the `ftpd_process` table reflects an audit and verification of files resident on S3. Unlike `ftpd_log` this log only deals with successful transfers. The goal is to identify any file hash mismatches, corruptions or other problems that may impact the veracity of the files on S3. While there is some overlap with `ftpd_log`, this log is is meant to be authoritative for auditing a successful transfer.


```sql
CREATE TABLE IF NOT EXISTS `ftpd_process` (
  `id` INT(10) unsigned NOT NULL AUTO_INCREMENT DEFAULT NULL,
  `path_hash` VARCHAR(512) NOT NULL,
  `file_hash` VARCHAR(512) NOT NULL,
  `file_hash_type` VARCHAR(6) NOT NULL DEFAULT '',
  `bucket` VARCHAR(255) NOT NULL DEFAULT '',
  `file_path` VARCHAR(1024) NOT NULL DEFAULT '',
  `file_linecount` VARCHAR(256) NOT NULL DEFAULT '',
  `file_size` VARCHAR(256) NOT NULL DEFAULT '',
  `process_status` TINYINT(1)NOT NULL,
  `modified` TIMESTAMP NOT NULL DEFAULT NOW(),
  `accessed` TIMESTAMP NOT NULL DEFAULT NOW() ON UPDATE now(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='ProFTP file processed table';
```


```bash
+----+----------------------------------+----------------------------------+----------------+--------------+---------------------------------+----------------+-----------+----------------+---------------------+---------------------+
| id | path_hash                        | file_hash                        | file_hash_type | bucket       | file_path                       | file_linecount | file_size | process_status | modified            | accessed            |
+----+----------------------------------+----------------------------------+----------------+--------------+---------------------------------+----------------+-----------+----------------+---------------------+---------------------+
|  1 | a2f65667aed12e1eb7184b7030f1efe1 | a7f41a2b49a84b4f6e89e59c723def89 | MD5            | my-s3-test | /mnt/ebs/ftpd/tester/664708.zip | 0              | 6733763   |              1 | 2019-01-09 01:30:02 | 2019-01-09 01:30:02 |
+----+----------------------------------+----------------------------------+----------------+--------------+---------------------------------+----------------+-----------+----------------+---------------------+---------------------+
```

A background process is responsible for updating `ftpd_process` and `ftpd_log`


### Processing Status Codes
Status codes for `ftpd_log` and `ftpd_process` denote the state of a file that has been delivered to the server.

*  **0** = Unprocessed
*  **1** = Transfer and checksum successfully processed. Success!
*  **2** = There was an error in the file transfer to AWS. Could be a network or application failure
*  **3** = The file checksum between the original file and the one on s3 does not match
*  **4** = The file can not be found locally or on S3. Upload may have aborted or the file was deleted by the user
*  **5** = The file successful transferred over the network, but is not a supported file type. This will occur if you place restrictions on file types. For example, a user trying to upload a `PNG` would get a status code file if the supported are: `(*.csv | *.txt | *.tsv | *.gz | *.tgz | *.zip)`
*  **6** = The was a hard failure of the file transfer. This be be due to transfer, user, file or other error

## Status Codes

A `"response_code":"226"` in a log file indicates success.

However, there are other status codes that may be present. See below:

* accepts the STOR request with code `226` if the entire file was successfully received and stored
* rejects the STOR request with code `425` if no TCP connection was established
* rejects the STOR request with code `426` if the TCP connection was established but then broken by the client or by network failure or
* rejects the STOR request with code `451`, `452`, or `552` if the server had trouble saving the file to disk.


See https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes

**NOTE**: If any "reject" codes are present, then you will want to have a workflow for further consideration.



# Monitoring
Services in the container are monitored via `Monit`. Monit is orchestrating the automated monitoring for various health and upkeep operations. For example, here are a few operations it cares for:

* Server `PID` process
* Server `PORT`
* Server `DISK` size
* `MYSQL` Database existence check
* `MYSQL` Database write check
* `Volume` mount check
* `CACHE` check
* CROND `PID` process

One thing to note is that if `Monit` detects a problem it will issue a STOP command. If you are using a Docker `--restart unless-stopped` in your docker run command this will trigger the server to automatically restart. While not activated, you can pair these checks and tests with Slack notifications (**not included**).

## Examples
The following reflects a Monit config to monitor the server application and associated processes for `ports` , `disk` and others. You can find a collection of similar configs in `etc/monit.d/*`.

```bash
### proftpd
check process s3sftp-server
    matching "proftpd"
    start program = "/usr/sbin/proftpd -c /etc/proftpd/proftpd.conf" with timeout 60 seconds
    stop program = "/bin/bash -c 'pkill syslogd'"
    if 3 restarts within 5 cycles then stop
    if cpu > 90% for 8 cycles then stop

check host s3sftp-server-port with address {{LOCALIPV4}}
     every 10 cycles
     start program = "/usr/sbin/proftpd -c /etc/proftpd/proftpd.conf" with timeout 60 seconds
     stop program = "/bin/bash -c 'pkill syslogd'"
     if failed port {{APP_PORT}} for 10 cycles then stop

check filesystem s3sftp-disk-size with path /
     every 5 cycles
     start program = "/usr/sbin/proftpd -c /etc/proftpd/proftpd.conf" with timeout 60 seconds
     stop program = "/bin/bash -c 'pkill syslogd'"
     if space usage > 95% for 5 cycles then stop

check program s3sftp-health-check with path "/bin/bash -c '/tests/test_proftpd.sh'"
    every 5 cycles
    start program = "/usr/sbin/proftpd -c /etc/proftpd/proftpd.conf" with timeout 60 seconds
    stop program = "/bin/bash -c 'pkill syslogd'"
    if status != 0 for 2 cycles then stop
```

# Internalization and Localization

Openbridge supports UTF-8 filename character sets. The system will perform any character set decoding checks as the file is being delivered and will automatically discover the encoding used.

**Please note**: While our system tries to do the requested encoding/decoding for UTF-8, if operations fail it continues using the bytes as sent by the client. While the process fails gracefully and allows the delivery of the file in this situation there is no guarantee that downstream data processing pipelines will work properly. Please verify prior to delivery of data that it is properly encoded to UTF-8 standards.

# Blocked Files

To help protect the integrity of the data sent to Openbridge, we do not allow you to deliver files of certain types (such as.exe files) because of their potential for introducing a unwanted or malicious software threats. By default, we block these files:

```bash
(ade|adp|app|ai|asa|ashx|asmx|asp|bas|bat|cdx|cer|cgi|chm|class|cmd|com|config|cpl|crt|csh|dmg|doc|docx|dll|eps|exe|fxp|ftaccess|hlp|hta|htr|htaccess|htw|html|htm|ida|idc|idq|ins|isp|its|jse|ksh|lnk|mad|maf|mag|mam|maq|mar|mas|mat|mau|mav|maw|mda|mdb|mde|mdt|mdw|mdz|msc|msh|msh1|msh1xml|msh2|msh2xml|mshxml|msi|msp|mst|ops|pdf|php|php3|php4|php5|pcd|pif|prf|prg|printer|pst|psd|rar|reg|rem|scf|scr|sct|shb|shs|shtm|shtml|soap|stm|tgz|taz|url|vb|vbe|vbs|ws|wsc|wsf|wsh|xls|xlsx|xvd)
```

Hidden files are also not allowed. These files have a prefix of "`.`" or "`..`"

```
.file.txt
.file.csv
..file
```

Any files uploaded meeting the criteria listed in "Blocked Files" will result the transfer being rejected.

# DNS-based Blackhole List (DNSBL) / Real-time Blackhole List (RBL)
Openbridge employs a DNSBL (commonly known as a "Blocklist"). This is a database that is queried in realtime for the purpose of obtaining an opinion on the origin of incoming hosts. The role of a DNSBL is to assess whether a particular IP Address meets acceptance policies of inbound connections. DNSBL is often used by email, web and other network services for determining and rejecting addresses known to be sources of spam, phishing and other unwanted behavior.

More information on DNS blacklists can be found here: http://en.wikipedia.org/wiki/DNSBL

# Account Ban and Lockout
Openbridge employs a dynamic "ban" lists that prevents the banned user or host from logging in to the server. This will occur if our system detects 4 incorrect login attempts. The ban will last for approximately 30 minutes at which time you can attempt to login again. If you continue to have difficulties please contact support.

Openbridge can also use **[Autoban](https://github.com/openbridge/ob_APP_autoban)**, a package that leverages `mod_wrap2` to detect malicious login attempts and ban them.

# IP Blacklist and Whitelist
Access can be controlled via `ftpd_allow` and `ftpd_deny` tables.

Below is an example of the **allow** table with allow IP addresses.

```bash
+----------------+---------+---------+---------------------+---------------------+
| client_ip      | allowed | options | modified            | accessed            |
+----------------+---------+---------+---------------------+---------------------+
| 11.11.22.134  | ALL     | ALLOWED | 2019-01-09 01:45:04 | 2019-01-09 01:45:04 |
| 2.4.96.175    | ALL     | ALLOWED | 2019-01-09 01:45:04 | 2019-01-09 01:45:04 |
| 45.48.112.77  | ALL     | ALLOWED | 2019-01-09 01:45:05 | 2019-01-09 01:45:05 |
| 34.32.175.2   | ALL     | ALLOWED | 2019-01-09 01:45:05 | 2019-01-09 01:45:05 |
| 66.4.9.2      | ALL     | ALLOWED | 2019-01-09 01:45:05 | 2019-01-09 01:45:05 |
+----------------+---------+---------+---------------------+---------------------+
```
# Idle Connection Time Limits
The app sets the maximum number of seconds a connection between the server and a client after the client has successfully authenticated. This is typically 10 minutes or 600 seconds in length. If you are idle for longer than this time allotment the server will think you are finished and disconnect your client. If this occurs a client will simply need to reconnect.

# Encrypting Your Databases Connections

When setting up the MYSQL or MariaDB instance, you may want the application level connection using SSL. The first step is to set the `GRANT` for the user and specify SSL

```sql
GRANT USAGE ON *.* TO 'name'@<host REQUIRE SSL;
```
Flush when complete:

```sql
FLUSH PRIVILEGES;
```

Test the connection
```bash
mysql -h 'server'.rds.amazonaws.com --ssl_ca=/etc/pki/tls/rds-combined-ca-bundle.pem --ssl-verify-server-cert -u 'name' -p'password with no space between p and pass' -e "show status like 'Ssl_cipher';"
```
And you will see something like that:
```bash
+---------------+------------+
| Variable_name | Value      |
+---------------+------------+
| Ssl_cipher    | AES256-SHA |
+---------------+------------+
```

The service has a `my.conf.d/client.cnf` file which is included in the build. This relies on AWS certs/keys. If you are deploying this outside AWS take note of this fact and adjust accordingly.

Details from AWS
http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_MySQL.html#MySQL.Concepts.SSLSupport

# Hash Validation
The service will perform an MD5 checksum of a completed transfer and of the file at rest on Amazon S3. This test ensures that the received file at the server level matches what is resident within S3.

## Considerations
Depending on the file size and the hash function, it takes a fair amount of CPU and IO resources to calculate the result.

* Only works for binary, not ASCII, uploads/downloads
* Only works for uploads (STOR) and downloads (RETR), but not for appends (APPE) or resumed uploads/downloads (REST + RETR/STOR)

See the `Logging` section for details on how the hash validation process is logged

# GeoIP Filters
You can the ability to block connections based on GeoIP. For example, in this case deny access to specific country IDs:

```bash
<IfModule mod_geoip.c>
   GeoIPEngine      on
   GeoIPTable       /etc/geoip/GeoIP.dat MemoryCache UTF8
   GeoIPTable       /etc/geoip/GeoLiteCity.dat MemoryCache UTF8
   GeoIPDenyFilter CountryCode (CN|IR|KN)
</IfModule>
```
If you do not want to use this feature, simply set `GeoIPEngine` to off:

```bash
GeoIPEngine      off
```

# Anti-Virus, Malware and Trojans
You can employ an anti-virus toolkit to scan for viruses, trojans, and other questionable items to prevent them from ever being uploaded to our system. The process is designed to detect in real-time threats present in any incoming files.

This means any file sent to your system will be scanned prior to be fully written to the filesystem. Any files uploaded meeting your scan rejection criteria will be viewed as a threat and be rejected.

A running ClamAV service is required for this to work. To activate ClamAV scanning, activate via the `env` file by setting the status to `CLAMD_STATUS` and `CLAMD_HOST`:

```bash
CLAMD_STATUS=on
CLAMD_HOST=172.24.0.1
```

# FTP

Openbridge does support the use of FTP/FTPS as part of the provided configuration files. We recognize that there are some systems that can only deliver data via FTP. For example, many of the Adobe export processes occur via FTP. However, it should be noted that the use of FTP offers no encryption security for connection and data transport. We strongly recommend the use of SFTP or FTPES whenever possible.

# Sample SQL Queries

Example commands.
```sql
INSERT INTO ftpd_salt (userid, salt) VALUES ('tester', 'n74f624573q47ddaa4d4aaf6ff1c465d695e0a94ace0784zz801ffbd73d6dd9b') ON DUPLICATE KEY UPDATE salt='n74f624573q47ddaa4d4aaf6ff1c465d695e0a94ace0784zz801ffbd73d6dd9b';
```

```sql
ALTER TABLE ftpd_quotalimit rename column userid to name;
```
```sql
CREATE INDEX users ON ftpd_user(userid) USING HASH;
```
```sql
INSERT INTO `ftpd_quotalimit` (`name`, `quota_type`, `per_session`, `limit_type`, `bytes_in_avail`, `bytes_out_avail`, `bytes_xfer_avail`, `files_in_avail`, `files_out_avail`, `files_xfer_avail`) VALUES ('tester', 'user', 'false', 'soft', 214748364800, 214748364800, 214748364800, 1000, 1000, 1000);
```
```sql
UPDATE ftpd_user SET passwd='c637ab6550b7ed1813f77aaaad836d9d2bb52e489697d699ae7406e3e64a7e7f' WHERE userid='tester';
```
```sql
UPDATE ftpd_user SET status='inactive' WHERE userid='tester';
```
```sql
INSERT IGNORE INTO ftpusers (id, userid, passwd, subscriptionid, uid, gid, homedir, status, shell, count, accessed, modified) VALUES ('', 'foobar', 'f4270936c0a84ef714a99999f2438fd421f95994e64b1165d77be989936cdf43','test', 2001, 2001, '/tmp/tester', 'active', '/sbin/nologin', 0, '', '');
```
```sql
UPDATE ftpd_user SET homedir='/mnt/ebs/ftpd/foobar-00022' WHERE userid='foobar';
```
```sql
DELETE from ftpd_user where userid = foobar;
```
```sql
INSERT INTO `ftpd_quotalimit` (`userid`, `quota_type`, `per_session`, `limit_type`, `bytes_in_avail`, `bytes_out_avail`, `bytes_xfer_avail`, `files_in_avail`, `files_out_avail`, `files_xfer_avail`) VALUES ('tester', 'user', 'true', 'hard', 15728640, 15728640, 15728640, 100, 100, 100);
```
```sql
INSERT INTO ftpd_quotatally (`userid`, bytes_in_used`, `bytes_out_used`, `bytes_xfer_used`, `files_in_used`, `files_out_used`, `files_xfer_used`) VALUES ('tester', 0, 0, 0, 0, 0, 0);
```
```sql
mysql -h ${MYSQL_HOST} -u ${APP_SYSTEM_USER} -p${APP_SYSTEM_PASSWORD} -e "use $APP_DATABASE; INSERT INTO ftpd_group (groupname, gid, members) VALUES ('ftpgroup', '2001', 'tester');"
```
```sql
UPDATE ftpd_user SET homedir='/mnt/ebs/share/foobar-00022/foobar/foobar-external' WHERE userid='foobar-external';
```

```sql
UPDATE ftpd_log SET process_status='6' WHERE transfer_status='failed';
```
# Versioning
Here are the latest releases:

| Docker Tag | Git Hub Release |  Version | Alpine Version |
|-----|-------|-----|--------|
| latest | master  | 1.3.7 | 3.7 |


# TODO


# Issues

If you have any problems with or questions about this image, please contact us through a GitHub issue.

# Contributing

You are invited to contribute new features, fixes, or updates, large or small; we are always thrilled to receive pull requests, and do our best to process them as fast as we can.

Before you start to code, we recommend discussing your plans through a GitHub issue, especially for more ambitious contributions. This gives other contributors a chance to point you in the right direction, give you feedback on your design, and help you find out if someone else is working on the same thing.

# References
