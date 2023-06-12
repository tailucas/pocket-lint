<a name="readme-top"></a>

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

![Runtime Status](https://healthchecks.io/badge/ca7d337d-2b9c-4a7d-a006-5f83b6/7Z59nzjP-2/pocket-lint.svg)

## About The Project

This Docker application runs a [Python Telegram Bot](https://python-telegram-bot.org/) instance that offers management of items in a user's [Pocket][pocket-url] account. This application extends my own [boilerplate application][baseapp-url] hosted in [docker hub][baseapp-image-url] and takes its own git submodule dependency on my own [package][pylib-url]. This documentation covers the bot Python project; for user documentation see my [github page][botdocs-url] for this project.

Basic features of this bot application:

* This Docker application inherits all runtime features discussed in the [base application](https://github.com/tailucas/base-app#readme-top).
* Configures, enables and tracks a free-tier [ngrok tunnel][ngrok-url] to receive OAuth call-backs from Pocket during the [authentication workflow](https://getpocket.com/developer/docs/authentication).
* Stores authentication tokens, encrypted at rest, in a local [SQLite][sqlite-url] database and supports backups to AWS S3.
* Offers various bot commands to the user, and persists pick positions using digests if referencing user tags.
* Conforms with Telegram's v20 API which uses the Python [asyncio](https://docs.python.org/3/library/asyncio.html) paradigm to manage inherently asynchronous bot user activities. Due to this, the project also takes advantage of [SQLAlchemy](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html) asyncio bindings to their SQLite interface.

### What user content is stored?

This is one of the most important reasons to open-source such a project. As far as possible, the absolute minimum information is stored in a local database with the bot. Under `INFO` level logging, no user-specific information is logged to the application logs other than tracking essential bot activity. Authentication tokens that allow the bot to interact with the Pocket APIs need to be persisted by the bot and are encrypted at rest using the [AES cipher in GCM mode](https://www.pycryptodome.org/src/cipher/modern#gcm-mode). User preferences are keyed using the Telegram user ID and pick positions that include tags stored as [SHA384 digests](https://www.pycryptodome.org/src/hash/hash).

* [Database models](https://github.com/tailucas/pocket-lint/blob/main/app/database.py)
* [Crypto implementation](https://github.com/tailucas/pocket-lint/blob/main/app/crypto.py)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

Technologies that help make this package useful:

[![1Password][1p-shield]][1p-url]
[![Amazon AWS][aws-shield]][aws-url]
[![InfluxDB][influxdb-shield]][influxdb-url]
[![ngrok][ngrok-shield]][ngrok-url]
[![Pocket][pocket-shield]][pocket-url]
[![Poetry][poetry-shield]][poetry-url]
[![Python][python-shield]][python-url]
[![Sentry][sentry-shield]][sentry-url]
[![SQLite][sqlite-shield]][sqlite-url]
[![ZeroMQ][zmq-shield]][zmq-url]

Also:

* [Cronitor][cronitor-url]
* [Healthchecks][healthchecks-url]
* [Starlette](https://www.starlette.io/)
* [SQLAlchemy](https://www.sqlalchemy.org/)
* [Uvicorn](https://www.uvicorn.org/)

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- GETTING STARTED -->
## Getting Started

Here is some detail about the intended use of this package.

### Prerequisites

Beyond the Python dependencies defined in the [Poetry configuration](pyproject.toml), the package init carries hardcoded dependencies on [Sentry][sentry-url] and [1Password][1p-url] in order to function. Unless you want these and are effectively extending my [base project][baseapp-url], you're likely better off forking this package and cutting out what you do not need.

### Installation

0. :stop_sign: This project uses [1Password Secrets Automation][1p-url] to store both application key-value pairs as well as runtime secrets. It is assumed that the connect server containers are already running on your environment. If you do not want to use this, then you'll need to fork this package and make the changes as appropriate. It's actually very easy to set up, but note that 1Password is a paid product with a free-tier for secrets automation. Here is an example of how this looks for my application and the generation of the docker-compose.yml relies on this step. Your secrets automation vault must contain an entry called `ENV.pocket_lint` with these keys:

* `DEVICE_NAME`: For naming the container. This project uses `pocket-lint`.
* `APP_NAME`: Used for referencing the application's actual name for the logger. This project uses `pocket_lint`.
* `OP_CONNECT_SERVER`, `OP_CONNECT_TOKEN`, `OP_CONNECT_VAULT`: Used to specify the URL of the 1Password connect server with associated client token and Vault ID. See [1Password](https://developer.1password.com/docs/connect/get-started#step-1-set-up-a-secrets-automation-workflow) for more.
* `AWS_CONFIG_FILE`: Standard local location of the AWS configuration file. This project uses `/home/app/.aws/config`.
* `HC_PING_URL`: [Healthchecks][healthchecks-url] URL of this application's current health check status.
* `CRONITOR_MONITOR_KEY`: Token to enable additional health checks presented in [Cronitor][cronitor-url]. This tracks thread count and overall health.
* `AWS_DEFAULT_REGION`: Used by AWS tools like S3 backup location.
* `NGROK_ENABLED`: Enables download and configuration of [ngrok][ngrok-url] client.
* `TABLESPACE_PATH`: The location of the physical SQLite tablespace created by the application. This project uses `/data/pocket_lint.db`.
* `INFLUXDB_BUCKET`: The configured bucket in InfluxDB that records some application telemetry.
* `TELEGRAM_BOT_LINK`: The link to Telegram's short URL. This project uses `http://t.me/PocketLintBot`.
* `HELP_URL`: Used to specify the location of the user help. This project uses `https://tailucas.github.io/pocket-lint/`.

With these configured, you are now able to build the application.

In addition to this, [additional runtime configuration](https://github.com/tailucas/pocket-lint/blob/f6d258e935c01bba2e8a18132278b8161b576501/app/__main__.py#L13-L21) is used by the application, and also need to be contained within the secrets vault. With these configured, you are now able to run the application.

1. Clone the repo
   ```sh
   git clone https://github.com/tailucas/pocket-lint.git
   ```
2. Verify that the git submodule is present.
   ```sh
   git submodule init
   git submodule update
   ```
4. Make the Docker runtime user and set directory permissions. :hand: Be sure to first review the Makefile contents for assumptions around user IDs for Docker.
   ```sh
   make user
   ```
5. Now generate the docker-compose.yml:
   ```sh
   make setup
   ```
6. And generate the Docker image:
   ```sh
   make build
   ```
7. If successful and the local environment is running the 1Password connect containers, run the application. For foreground:
   ```sh
   make run
   ```
   For background:
   ```sh
   make rund
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->
## Usage

Assuming that you've already [configured a Telegram bot](https://core.telegram.org/bots/faq#how-do-i-create-a-bot), running this application will bring the bot to life.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- LICENSE -->
## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [PyCryptodome](https://github.com/Legrandin/pycryptodome)
* [Pocket client for Python](https://github.com/tapanpandita/pocket)
* [Template on which this README is based](https://github.com/othneildrew/Best-README-Template)
* [All the Shields](https://github.com/progfay/shields-with-icon)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/tailucas/pocket-lint.svg?style=for-the-badge
[contributors-url]: https://github.com/tailucas/pocket-lint/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/tailucas/pocket-lint.svg?style=for-the-badge
[forks-url]: https://github.com/tailucas/pocket-lint/network/members
[stars-shield]: https://img.shields.io/github/stars/tailucas/pocket-lint.svg?style=for-the-badge
[stars-url]: https://github.com/tailucas/pocket-lint/stargazers
[issues-shield]: https://img.shields.io/github/issues/tailucas/pocket-lint.svg?style=for-the-badge
[issues-url]: https://github.com/tailucas/pocket-lint/issues
[license-shield]: https://img.shields.io/github/license/tailucas/pocket-lint.svg?style=for-the-badge
[license-url]: https://github.com/tailucas/pocket-lint/blob/main/LICENSE

[baseapp-url]: https://github.com/tailucas/base-app
[baseapp-image-url]: https://hub.docker.com/repository/docker/tailucas/base-app/general
[pylib-url]: https://github.com/tailucas/pylib
[tailucas-url]: https://github.com/tailucas
[botdocs-url]: https://tailucas.github.io/pocket-lint/

[1p-url]: https://developer.1password.com/docs/connect/
[1p-shield]: https://img.shields.io/static/v1?style=for-the-badge&message=1Password&color=0094F5&logo=1Password&logoColor=FFFFFF&label=
[aws-url]: https://aws.amazon.com/
[aws-shield]: https://img.shields.io/static/v1?style=for-the-badge&message=Amazon+AWS&color=232F3E&logo=Amazon+AWS&logoColor=FFFFFF&label=
[cronitor-url]: https://cronitor.io/
[healthchecks-url]: https://healthchecks.io/
[influxdb-shield]: https://img.shields.io/static/v1?style=for-the-badge&message=InfluxDB&color=22ADF6&logo=InfluxDB&logoColor=FFFFFF&label=
[influxdb-url]: https://www.influxdata.com/
[ngrok-url]: https://ngrok.com/
[ngrok-shield]: https://img.shields.io/static/v1?style=for-the-badge&message=ngrok&color=1F1E37&logo=ngrok&logoColor=FFFFFF&label=
[pocket-url]: https://getpocket.com/
[pocket-shield]: https://img.shields.io/static/v1?style=for-the-badge&message=Pocket&color=EF3F56&logo=Pocket&logoColor=FFFFFF&label=
[poetry-url]: https://python-poetry.org/
[poetry-shield]: https://img.shields.io/static/v1?style=for-the-badge&message=Poetry&color=60A5FA&logo=Poetry&logoColor=FFFFFF&label=
[python-url]: https://www.python.org/
[python-shield]: https://img.shields.io/static/v1?style=for-the-badge&message=Python&color=3776AB&logo=Python&logoColor=FFFFFF&label=
[sentry-url]: https://sentry.io/
[sentry-shield]: https://img.shields.io/static/v1?style=for-the-badge&message=Sentry&color=362D59&logo=Sentry&logoColor=FFFFFF&label=
[sqlite-url]: https://www.sqlite.org/
[sqlite-shield]: https://img.shields.io/static/v1?style=for-the-badge&message=SQLite&color=003B57&logo=SQLite&logoColor=FFFFFF&label=
[zmq-url]: https://zeromq.org/
[zmq-shield]: https://img.shields.io/static/v1?style=for-the-badge&message=ZeroMQ&color=DF0000&logo=ZeroMQ&logoColor=FFFFFF&label=
