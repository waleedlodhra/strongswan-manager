# Documentation

## setup.py
Tool to install strongswan_manager comfortably.
```bash
./setup.py <command> [options]
```

- -v | --verbose
    - Sets the output of setup.py verbose.

### install
```bash
./setup.py install [-p %python-interpreter%]
```
Makes strongswan_manager ready to run.

- -p | --python %python-interpreter%
    - Select a specific python interpreter to run strongswan_manager
    - python3 is used as default value for %python-interpreter%

### uninstall
```bash
sudo ./setup.py uninstall
```
Undos the installation.
Run this command as root to remove the strongswan_manager systemd service.

### add-service
```bash
sudo ./setup.py add-service
```
Adds strongswan_manager as a systemd service. The service will be disabled and stopped.

Enable (start strongswan_manager at system startup) and start it with the following commands:
```bash
sudo systemctl enable strongswan_manager.service
sudo systemctl start strongswan_manager.service
```

You need root permissions to run add-service.

### remove-service
```bash
sudo ./setup.py remove-service
```
Removes the strongswan_manager systemd service.
You need root permissions to run this command.

### migrate
```bash
./setup.py migrate [-dm]
```
Runs the django migrations like descripted in [migrations](https://docs.djangoproject.com/en/1.9/topics/migrations/).
This command is mainly for developers.

- -dm | --delete-migrations
    - Deletes all old migrations scripts and also the sqlite database.