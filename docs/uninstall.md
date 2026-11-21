# Uninstall

Removing the server does not remove agents from other machines. To do that, see
[Remove an agent](agents.md#remove-an-agent).

## Docker

```bash
./docker/cleanup.sh               # asks first; --yes skips the question, --keep-env keeps .env
```

This removes the containers, all data, the built images and `.env`. It removes the public images
(postgres, redis, kafka, alpine) only if they were not on your machine before
`./docker/init-env.sh` ran. Images you already had stay.

To stop and delete the containers but keep the data, use `docker compose down` instead.

## Script install

```bash
./uninstall.sh                    # asks before purging; --yes skips the question
./uninstall.sh --keep-packages    # leaves every system package alone
```

It stops and removes the Vajra services and drops the `vajra_db` and `fleet` databases and the
`vajra` database role. It also deletes:

- the nginx site and web files
- build output
- certificates and generated keys
- `.install.env` and `admin-credentials.txt`

### How packages are handled

Before it changes anything, `./install.sh` saves a list of the packages already on the machine in
`.install-snapshot/`. `./uninstall.sh` uses that list:

- It only removes packages from a fixed list of what Vajra installs: PostgreSQL, Redis, nginx,
  Node.js, the build tools and libraries, Java and Grafana. Of those, it only removes the ones that
  were not on the machine before.
- It never removes anything else. Desktop, login and system packages are safe, and it always
  keeps common tools such as python3, curl, git and openssl.
- If removing a package would also remove something outside that list, it removes nothing and says
  so.
- Packages that were already installed stay. Only Vajra's data is removed from them.
