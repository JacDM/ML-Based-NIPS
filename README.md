# NetFlow-Based-ML-NIPS on Docker

Most of the documentation, mutch like the base ELK implementation is from Anthony Lapenna AKA [deviantony](https://github.com/deviantony) used under his MIT License

[![Elastic Stack version](https://img.shields.io/badge/Elastic%20Stack-8.13.1-00bfb3?style=flat&logo=elastic-stack)](https://www.elastic.co/blog/category/releases)

Based on the [official Docker images][elastic-docker] from Elastic:

* [Elasticsearch](https://github.com/elastic/elasticsearch/tree/main/distribution/docker)
* [Elastiflow](https://hub.docker.com/r/elastiflow/flow-collector)
* [Kibana](https://github.com/elastic/kibana/tree/main/src/dev/build/tasks/os_packages/docker_generator)
* [Python 3.9](https://hub.docker.com/_/python)


---
## Installation
Clone this repository onto the Docker host that will run the stack with the command below:
```sh
git clone https://github.com/JacDM/ML-Based-NIPS.git
```
Navigate to the directory
```sh
cd ML-Based-NIPS
```
Wait for Elasticsearch to start, if the setup container faile, run it again and elasticsearc should be up. 
```sh
docker-compose up setup
```
The next command is to start all other containers as they all depend on Elasticsearch
```sh
docker-compose up
```
## Machine Learning & Deep Learning Experimentation
To run the jupyter Notebook, you need to download and extract the dataset into a folder called NF-ToN-IoT-v2 within the Data Sets folder. you can then run the file up to the Decision Tree section at which point, the modified and reduces dataset should be saved and you don't have to run that section again which makes things easier.
yuou can also skip that and use the already preprocessed files by running the second part and only running the `For Neural Networks` cell when testing ANN's.

## Running the NIPS
By default it should run automatically, in the case that it takes too long or dosent start, you can execute:
```sh
python app.py
```
to start the app manually, or just run it independently from the compose on your hosts system which is my favorite method of doing it as you dent have to fiddle with global docker variables.

## Setting up NIPS Parameters
```python
esClient = Elasticsearch('http://localhost:9200', basic_auth=["elastic", "changeme"])
    hostIP = "127.0.0.1" # used to open SSH Client to your host OS to add firewall rules.
    username = "NIPS"  # Replace with your username
    password = "passwd"  # Replace with your password
    consoleLogLevel = 1 #Replace with desired log level
    nipsMode = 1 #Enables IP Blockinf if attack is detected
    timeFrame = "5m" #Defines timeframe to lookback from for elastic
    modelsPATH = "app/config/models/" # Path where models are stored
```
These parameters can are hardcoded and if you run them on your host OS then they will be user, also make sure all packages listed in app/Dockerfile are installed in your host if you want to run the script on your host. Make sure sklearn is version 1.4.1-post1

However if you run it via docker, then you dont need to wwory aboyut the packages as they will install themselves.

## Setting up SSH
Also for NIPS to work you need to setup an ssl server on the host, for windows you can follow the [Tutorial](https://petri.com/the-ultimate-guide-to-installing-openssh-on-windows/) 

## Setting up nProbe
> [!WARNING]
> nProbe requires a licence to generate flows, contact ntop team to request an educational licence for free, i cannot share mine as they are linked to my VM and will not work on another machine

install nprobe from the ntop website and setup the licence file, and run the code bellow after navigating to the install directory/bin
```sh
.\nprobe /c -i ’Intel(R) PRO/1000 MT Network Connection #3’ -V 9 -b 1 -t 60 -o
1 --export-template -T " %IPV4_SRC_ADDR %L4_SRC_PORT %IPV4_DST_ADDR
%L4_DST_PORT %PROTOCOL %FLOW_DURATION_MILLISECONDS %TCP_WIN_MAX_IN
%DURATION_OUT %MAX_TTL %L7_PROTO %SRC_TO_DST_AVG_THROUGHPUT %SHORTEST_FLOW_PKT
%MIN_IP_PKT_LEN %TCP_WIN_MAX_OUT %OUT_BYTES %FIRST_SWITCHED %LAST_SWITCHED "
```
-V, specifies the netflow format used, -t is the timeout for active conversations and -T
specifies the features we want to be sent in the flow.



## Setting up Kibana
While kibana works, you need to setup certain things to make flows enter python and make visualization easy, first head to the discover panel and create a new data view, 

![Elastiflow view setup](Figures/1.png "Elastiflow view setup")

after elastiflow sends some flows to elastic, you can enter `elastic*` in the index pattern field and select `@Timestamp` from the dropdown for the timestamp field. Name the view `elastiflow*` as well and save the view. if it matches some sources, amazing, if not, then nProbe is not sending data to elastic.
Remember if you dont see any data try changing the time frame on the top right of every page

![Elastiflow data View](Figures/Elastiflow.png "Elastiflow data View")

To get the visualizations like the one below:

![Elastiflow Sankey Diagram](Figures/ElastiflowSankey.png "Elastiflow Sankey Diagram")

its a little more involved:
* Navigate to the hamburger menu and scroll dowwn and click `management`
* Scroll down the list to the kibana section and click `saved objects`.
* from this page, hit the import button and grab the file located at k`ibana\Dashboard.ndjson` in this repo and import all 400 or so objects.
* Next navigate to `data views` within the kibana section of the leftward menu
* 3 new flows views will popup following the syntax `elastiflow-X-ecs*` click on each one click the edit button and change the index patern to `elastiflow*`
* Now when you go to any of the dashboards, some elements may be brocken as some IE that are parsed by elastiflow have different names. all you have to do is edit them and chose an appropriate feature to replace it. 
## Elastiflow
> [!WARNING]
> Elastiflow requires the free trial version to collect and parse nprobe Information Elements, the current credentials will expire on 11/05/2024, if it does you can go to elastiflows website and gain another account id and licence key.




## Contents

1. [Requirements](#requirements)
   * [Host setup](#host-setup)
   * [Docker Desktop](#docker-desktop)
     * [Windows](#windows)
     * [macOS](#macos)
1. [Usage](#usage)
   * [Cleanup](#cleanup)
   * [Version selection](#version-selection)
1. [Configuration](#configuration)
   * [How to configure Elasticsearch](#how-to-configure-elasticsearch)
   * [How to configure Kibana](#how-to-configure-kibana)
   * [How to configure Logstash](#how-to-configure-logstash)
   * [How to disable paid features](#how-to-disable-paid-features)
   * [How to scale out the Elasticsearch cluster](#how-to-scale-out-the-elasticsearch-cluster)
   * [How to re-execute the setup](#how-to-re-execute-the-setup)
   * [How to reset a password programmatically](#how-to-reset-a-password-programmatically)
1. [Extensibility](#extensibility)
   * [How to add plugins](#how-to-add-plugins)
   * [How to enable the provided extensions](#how-to-enable-the-provided-extensions)
1. [JVM tuning](#jvm-tuning)
   * [How to specify the amount of memory used by a service](#how-to-specify-the-amount-of-memory-used-by-a-service)
   * [How to enable a remote JMX connection to a service](#how-to-enable-a-remote-jmx-connection-to-a-service)
1. [Going further](#going-further)
   * [Plugins and integrations](#plugins-and-integrations)

## Requirements

### Host setup

* [Docker Engine][docker-install] version **18.06.0** or newer
* [Docker Compose][compose-install] version **1.28.0** or newer (including [Compose V2][compose-v2])
* 1.5 GB of RAM

> [!NOTE]
> Especially on Linux, make sure your user has the [required permissions][linux-postinstall] to interact with the Docker
> daemon.

By default, the stack exposes the following ports:

* 2055: ElastiFlow Netflow input
* 9200: Elasticsearch HTTP
* 9300: Elasticsearch TCP transport
* 5601: Kibana

> [!WARNING]
> Elasticsearch's [bootstrap checks][bootstrap-checks] were purposely disabled to facilitate the setup of the Elastic
> stack in development environments. For production setups, we recommend users to set up their host according to the
> instructions from the Elasticsearch documentation: [Important System Configuration][es-sys-config].

### Docker Desktop

#### Windows

If you are using the legacy Hyper-V mode of _Docker Desktop for Windows_, ensure [File Sharing][win-filesharing] is
enabled for the `C:` drive.

#### macOS
> [!WARNING]
> While the NIPS technically can run on a mac but it has not been tested and is not suported, Additionally, NIPS Mode, which blocks IP's will not work as there is no command for it so set the docker env variables and dockerfile defaults in the app folder accordingly.

The default configuration of _Docker Desktop for Mac_ allows mounting files from `/Users/`, `/Volume/`, `/private/`,
`/tmp` and `/var/folders` exclusively. Make sure the repository is cloned in one of those locations or follow the
instructions from the [documentation][mac-filesharing] to add more locations.

## Usage
> [!NOTE]
> The instructions bellow are straight from deviantony for troubleshooting and you should not need any of the following.

> [!IMPORTANT]
> [Platinum][subscriptions] features are enabled by default for a [trial][license-mngmt] duration of **30 days**. After
> this evaluation period, you will retain access to all the free features included in the Open Basic license seamlessly,
> without manual intervention required, and without losing any data. Refer to the [How to disable paid
> features](#how-to-disable-paid-features) section to opt out of this behaviour.

> [!WARNING]
> You must rebuild the stack images with `docker-compose build` whenever you switch branch or update the
> [version](#version-selection) of an already existing stack.


> [!NOTE]
> You can also run all services in the background (detached mode) by appending the `-d` flag to the above command.

Give Kibana about a minute to initialize, then access the Kibana web UI by opening <http://localhost:5601> in a web
browser and use the following (default) credentials to log in:

* user: *elastic*
* password: *changeme*

> [!NOTE]
> Upon the initial startup, the `elastic`, and `kibana_system` Elasticsearch users are intialized
> with the values of the passwords defined in the [`.env`](.env) file (_"changeme"_ by default). The first one is the
> [built-in superuser][builtin-users], the other two are used by Kibana and Logstash respectively to communicate with
> Elasticsearch. This task is only performed during the _initial_ startup of the stack. To change users' passwords
> _after_ they have been initialized, please refer to the instructions in the next section.

### Initial setup

#### Setting up user authentication

> [!NOTE]
> Refer to [Security settings in Elasticsearch][es-security] to disable authentication.

> [!WARNING]
> Starting with Elastic v8.0.0, it is no longer possible to run Kibana using the bootstraped privileged `elastic` user.

The _"changeme"_ password set by default for all aforementioned users is **unsecure**. For increased security, we will
reset the passwords of all aforementioned Elasticsearch users to random secrets.

1. Reset passwords for default users

    The commands below reset the passwords of the `elastic`and `kibana_system` users. Take note
    of them.

    ```sh
    docker-compose exec elasticsearch bin/elasticsearch-reset-password --batch --user elastic
    ```
    ```sh
    docker-compose exec elasticsearch bin/elasticsearch-reset-password --batch --user kibana_system
    ```

    If the need for it arises (e.g. if you want to [collect monitoring information][ls-monitoring] through Beats and
    other components), feel free to repeat this operation at any time for the rest of the [built-in
    users][builtin-users].

1. Replace usernames and passwords in configuration files

    Replace the password of the `elastic` user inside the `.env` file with the password generated in the previous step.
    Its value isn't used by any core component, but [extensions](#how-to-enable-the-provided-extensions) use it to
    connect to Elasticsearch.

    > [!NOTE]
    > In case you don't plan on using any of the provided [extensions](#how-to-enable-the-provided-extensions), or
    > prefer to create your own roles and users to authenticate these services, it is safe to remove the
    > `ELASTIC_PASSWORD` entry from the `.env` file altogether after the stack has been initialized.

    Replace the password of the `kibana_system` user inside the `.env` file with the password generated in the previous
    step. Its value is referenced inside the Kibana configuration file (`kibana/config/kibana.yml`).

    See the [Configuration](#configuration) section below for more information about these configuration files.

1. Restart Python and Kibana to re-connect to Elasticsearch using the new passwords

    ```sh
    docker-compose up -d python kibana
    ```

> [!NOTE]
> Learn more about the security of the Elastic stack at [Secure the Elastic Stack][sec-cluster].

### Cleanup

Elasticsearch data is persisted inside a volume by default.

In order to entirely shutdown the stack and remove all persisted data, use the following Docker Compose command:

```sh
docker-compose down -v
```

### Version selection

This repository stays aligned with the latest version of the Elastic stack. The `main` branch tracks the current major
version (8.x).

To use a different version of the core Elastic components, simply change the version number inside the [`.env`](.env)
file. If you are upgrading an existing stack, remember to rebuild all container images using the `docker-compose build`
command.

> [!IMPORTANT]
> Always pay attention to the [official upgrade instructions][upgrade] for each individual component before performing a
> stack upgrade.

Older major versions are also supported on separate branches:

* [`release-7.x`](https://github.com/deviantony/docker-elk/tree/release-7.x): 7.x series
* [`release-6.x`](https://github.com/deviantony/docker-elk/tree/release-6.x): 6.x series (End-of-life)
* [`release-5.x`](https://github.com/deviantony/docker-elk/tree/release-5.x): 5.x series (End-of-life)

## Configuration

> [!IMPORTANT]
> Configuration is not dynamically reloaded, you will need to restart individual components after any configuration
> change.

### How to configure Elasticsearch

The Elasticsearch configuration is stored in [`elasticsearch/config/elasticsearch.yml`][config-es].

You can also specify the options you want to override by setting environment variables inside the Compose file:

```yml
elasticsearch:

  environment:
    network.host: _non_loopback_
    cluster.name: my-cluster
```

Please refer to the following documentation page for more details about how to configure Elasticsearch inside Docker
containers: [Install Elasticsearch with Docker][es-docker].

### How to configure Kibana

The Kibana default configuration is stored in [`kibana/config/kibana.yml`][config-kbn].

You can also specify the options you want to override by setting environment variables inside the Compose file:

```yml
kibana:

  environment:
    SERVER_NAME: kibana.example.org
```

Please refer to the following documentation page for more details about how to configure Kibana inside Docker
containers: [Install Kibana with Docker][kbn-docker].

### How to configure Logstash

The Logstash configuration is stored in [`logstash/config/logstash.yml`][config-ls].

You can also specify the options you want to override by setting environment variables inside the Compose file:

```yml
logstash:

  environment:
    LOG_LEVEL: debug
```

Please refer to the following documentation page for more details about how to configure Logstash inside Docker
containers: [Configuring Logstash for Docker][ls-docker].

### How to disable paid features

You can cancel an ongoing trial before its expiry date — and thus revert to a basic license — either from the [License
Management][license-mngmt] panel of Kibana, or using Elasticsearch's `start_basic` [Licensing API][license-apis]. Please
note that the second option is the only way to recover access to Kibana if the license isn't either switched to `basic`
or upgraded before the trial's expiry date.

Changing the license type by switching the value of Elasticsearch's `xpack.license.self_generated.type` setting from
`trial` to `basic` (see [License settings][license-settings]) will only work **if done prior to the initial setup.**
After a trial has been started, the loss of features from `trial` to `basic` _must_ be acknowledged using one of the two
methods described in the first paragraph.

### How to scale out the Elasticsearch cluster

Follow the instructions from the Wiki: [Scaling out Elasticsearch](https://github.com/deviantony/docker-elk/wiki/Elasticsearch-cluster)

### How to re-execute the setup

To run the setup container again and re-initialize all users for which a password was defined inside the `.env` file,
simply "up" the `setup` Compose service again:

```console
$ docker-compose up setup
 ⠿ Container docker-elk-elasticsearch-1  Running
 ⠿ Container docker-elk-setup-1          Created
Attaching to docker-elk-setup-1
...
docker-elk-setup-1  | [+] User 'monitoring_internal'
docker-elk-setup-1  |    ⠿ User does not exist, creating
docker-elk-setup-1  | [+] User 'beats_system'
docker-elk-setup-1  |    ⠿ User exists, setting password
docker-elk-setup-1 exited with code 0
```

### How to reset a password programmatically

If for any reason your are unable to use Kibana to change the password of your users (including [built-in
users][builtin-users]), you can use the Elasticsearch API instead and achieve the same result.

In the example below, we reset the password of the `elastic` user (notice "/user/elastic" in the URL):

```sh
curl -XPOST -D- 'http://localhost:9200/_security/user/elastic/_password' \
    -H 'Content-Type: application/json' \
    -u elastic:<your current elastic password> \
    -d '{"password" : "<your new password>"}'
```

## Extensibility

### How to add plugins

To add plugins to any ELK component you have to:

1. Add a `RUN` statement to the corresponding `Dockerfile` (eg. `RUN logstash-plugin install logstash-filter-json`)
1. Add the associated plugin code configuration to the service configuration (eg. Logstash input/output)
1. Rebuild the images using the `docker-compose build` command

### How to enable the provided extensions

A few extensions are available inside the [`extensions`](extensions) directory. These extensions provide features which
are not part of the standard Elastic stack, but can be used to enrich it with extra integrations.

The documentation for these extensions is provided inside each individual subdirectory, on a per-extension basis. Some
of them require manual changes to the default ELK configuration.

## JVM tuning

### How to specify the amount of memory used by a service

The startup scripts for Elasticsearch and Logstash can append extra JVM options from the value of an environment
variable, allowing the user to adjust the amount of memory that can be used by each component:

| Service       | Environment variable |
|---------------|----------------------|
| Elasticsearch | ES_JAVA_OPTS         |
| Logstash      | LS_JAVA_OPTS         |

To accommodate environments where memory is scarce (Docker Desktop for Mac has only 2 GB available by default), the Heap
Size allocation is capped by default in the `docker-compose.yml` file to 512 MB for Elasticsearch and 256 MB for
Logstash. If you want to override the default JVM configuration, edit the matching environment variable(s) in the
`docker-compose.yml` file.

For example, to increase the maximum JVM Heap Size for Logstash:

```yml
logstash:

  environment:
    LS_JAVA_OPTS: -Xms1g -Xmx1g
```

When these options are not set:

* Elasticsearch starts with a JVM Heap Size that is [determined automatically][es-heap].
* Logstash starts with a fixed JVM Heap Size of 1 GB.

### How to enable a remote JMX connection to a service

As for the Java Heap memory (see above), you can specify JVM options to enable JMX and map the JMX port on the Docker
host.

Update the `{ES,LS}_JAVA_OPTS` environment variable with the following content (I've mapped the JMX service on the port
18080, you can change that). Do not forget to update the `-Djava.rmi.server.hostname` option with the IP address of your
Docker host (replace **DOCKER_HOST_IP**):

```yml
logstash:

  environment:
    LS_JAVA_OPTS: -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.ssl=false -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.port=18080 -Dcom.sun.management.jmxremote.rmi.port=18080 -Djava.rmi.server.hostname=DOCKER_HOST_IP -Dcom.sun.management.jmxremote.local.only=false
```

## Going further

### Plugins and integrations

See the following Wiki pages:

* [External applications](https://github.com/deviantony/docker-elk/wiki/External-applications)
* [Popular integrations](https://github.com/deviantony/docker-elk/wiki/Popular-integrations)

[elk-stack]: https://www.elastic.co/what-is/elk-stack
[elastic-docker]: https://www.docker.elastic.co/
[subscriptions]: https://www.elastic.co/subscriptions
[es-security]: https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html
[license-settings]: https://www.elastic.co/guide/en/elasticsearch/reference/current/license-settings.html
[license-mngmt]: https://www.elastic.co/guide/en/kibana/current/managing-licenses.html
[license-apis]: https://www.elastic.co/guide/en/elasticsearch/reference/current/licensing-apis.html

[elastdocker]: https://github.com/sherifabdlnaby/elastdocker

[docker-install]: https://docs.docker.com/get-docker/
[compose-install]: https://docs.docker.com/compose/install/
[compose-v2]: https://docs.docker.com/compose/compose-v2/
[linux-postinstall]: https://docs.docker.com/engine/install/linux-postinstall/

[bootstrap-checks]: https://www.elastic.co/guide/en/elasticsearch/reference/current/bootstrap-checks.html
[es-sys-config]: https://www.elastic.co/guide/en/elasticsearch/reference/current/system-config.html
[es-heap]: https://www.elastic.co/guide/en/elasticsearch/reference/current/important-settings.html#heap-size-settings

[win-filesharing]: https://docs.docker.com/desktop/settings/windows/#file-sharing
[mac-filesharing]: https://docs.docker.com/desktop/settings/mac/#file-sharing

[builtin-users]: https://www.elastic.co/guide/en/elasticsearch/reference/current/built-in-users.html
[ls-monitoring]: https://www.elastic.co/guide/en/logstash/current/monitoring-with-metricbeat.html
[sec-cluster]: https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html

[connect-kibana]: https://www.elastic.co/guide/en/kibana/current/connect-to-elasticsearch.html
[index-pattern]: https://www.elastic.co/guide/en/kibana/current/index-patterns.html

[config-es]: ./elasticsearch/config/elasticsearch.yml
[config-kbn]: ./kibana/config/kibana.yml
[config-ls]: ./logstash/config/logstash.yml

[es-docker]: https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html
[kbn-docker]: https://www.elastic.co/guide/en/kibana/current/docker.html
[ls-docker]: https://www.elastic.co/guide/en/logstash/current/docker-config.html

[upgrade]: https://www.elastic.co/guide/en/elasticsearch/reference/current/setup-upgrade.html
