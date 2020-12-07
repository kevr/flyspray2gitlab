# flyspray2gitlab

A collection of scripts that can be used to migrate bug tasks from Flyspray
to GitLab.

## flyspray<span>.</span>py

A script used to extract relevant columns from Flyspray's database into a JSON format.

**System Dependencies**<br>
* python3

**Python Dependencies**<br>
* pymsql

**Requirements**<br>
* Access to Flyspray's database.

```
usage: flyspray.py [-h] [--host HOST] [--port PORT] [--user USER]
                   [--password PASSWORD] [--database DATABASE]
                   [--prefix PREFIX]

optional arguments:
  -h, --help           show this help message and exit
  --host HOST          mysql server host (default: 'localhost')
  --port PORT          mysql server port (default: 3306)
  --user USER          mysql user (default: 'flyspray')
  --password PASSWORD  mysql password (default: 'flyspray')
  --database DATABASE  mysql database (default: 'flyspray')
  --prefix PREFIX      database table prefix (default: 'flyspray_')
```

After parsing the database, flyspray<span>.</span>py will write a JSON list of tasks to stdout. Below lies a shell snippet demonstrating the output JSON format of a task with a attachments and comments.

    $ ./flyspray
    [
        {
            "id": 5,
            "type": "Bug Report",
            "category": "Backend / Core",
            "project": "Default Project",
            "summary": "Attachment Test",
            "details": "Blah blah blah.",
            "opened_by": {
                "id": 1,
                "user_name": "kevr",
                "real_name": "Mr Super User",
                "jabber_id": "super@example.com",
                "email_address": "kevr@0cost.org",
                "account_enabled": true,
                "magic_url": ""
            },
            "priority_id": 2,
            "status": "New",
            "date_opened": 1607064642,
            "last_edited": 1607064642,
            "assigned": null,
            "closed": false,
            "resolution": "Not a bug",
            "version": "Development",
            "os": "All",
            "tags": [],
            "attachments": [
                {
                    "attachment_id": 3,
                    "task_id": 5,
                    "comment_id": 0,
                    "orig_name": "smart.png",
                    "file_name": "5_83f5fde1d8b131650efb53305188",
                    "file_type": "image/png; charset=binary",
                    "file_size": 187239,
                    "date_added": 1607064642
                }
            ],
            "comments": [
                {
                    "comment_id": 3,
                    "task_id": 5,
                    "date_added": 1607064659,
                    "comment_text": "Ha ha",
                    "last_edited_time": 1607064659,
                    "user": {
                        "id": 1,
                        "user_name": "kevr",
                        "real_name": "Mr Super User",
                        "jabber_id": "super@example.com",
                        "email_address": "kevr@0cost.org",
                        "account_enabled": true,
                        "magic_url": ""
                    },
                    "attachments": [
                        {
                            "attachment_id": 4,
                            "task_id": 5,
                            "comment_id": 3,
                            "orig_name": "minicom.log",
                            "file_name": "5_15135b2f68a0ef61fe1a0a793092",
                            "file_type": "text/plain; charset=us-ascii",
                            "file_size": 35,
                            "date_added": 1607064659
                        }
                    ]
                }
            ]
        }
    ]

That is all this program does.

## gitlab<span>.</span>py

A script used to import JSON from flyspray<span>.</span>py into a GitLab server by utilizing GitLab's v4 REST API.

**System Dependencies**<br>
* python3

**Python Dependencies**<br>
* requests
* prettytable

**Requirements**<br>
* JSON produced by flyspray<span>.</span>py.
* Access to Flyspray's `attachments` directory.
    * flyspray<span>.</span>py does not include attachment binary data in it's output JSON, only filenames that are held within the `attachments` directory. For this reason, gitlab<span>.</span>py needs access to the `attachments` directory (or at least a verbatim clone of it) to migrate attachments.
* GitLab access token of a user with API read/write permissions to the target repositories.
    * This user will be used to create issues and notes based on Flyspray tasks and comments.
* A fallback target repository (`--default-target`).
    * This is where all issues will be migrated to that do not match a mapping in `--project-mapping`.
* (Optional) A project mapping JSON file (`--project-mapping`).
    * See [doc/projects.map.json.example](/doc/projects.map.json.example).

```
usage: gitlab.py [-hv] [--skip-attachments] [-btmdua ARG] command

positional arguments:
  command                                                primary command (import, dry)

optional arguments:
  -h, --help                                             show this help message and exit
  -v, --verbose                                          enable debug logging
  -b BASE, --base BASE                                   GitLab base URL (default: 'http://gitlab.local.net')
  -t TOKEN, --token TOKEN                                GitLab migration user access token
  -m PROJECT_MAPPING, --project-mapping PROJECT_MAPPING  path to a project json mapping file (default: 'projects.map.json')
  -d DEFAULT_TARGET, --default-target DEFAULT_TARGET     default repository used as the import destination
  -u UPSTREAM, --upstream UPSTREAM                       Flyspray upstream base URL
  -a ATTACHMENTS, --attachments ATTACHMENTS              path to Flyspray attachments directory
  --api API                                              GitLab API version (default: 'v4')
  --skip-attachments                                     skip attachments altogether

valid commands:
  import                import stdin json into a gitlab instance
  dry                   a dry run of import

additional information:
  --project-mapping     a path to a json mapping file containing project (key) to
                        repository (value) mappings (see projects.map.json.example)
  --upstream            The upstream argument specifies an HTTP(S) base to use for
                        referencing back to users who made the original tasks and comments.

Example:
  $ flyspray.py | gitlab.py import -m projects.json

Note: This program reads stdin as input for flyspray json data.
```

You'll most likely want to supply a mapping file to direct different Flyspray projects to specific repositories on your GitLab target. Otherwise, only the default target will be used for all projects.

```
{
    "flysprayProject": "user/repo1",
    "flysprayBugs": "user/repo2"
}
```

The `--upstream` in this sense should be set to an originating Flyspray server which houses a `/user/:user_id` route akin to https://bugs.archlinux.org's implementation. This URL is used to link back to users who opened tasks or wrote comments in the original tasks.

## Rollback

If an exception is raised during the `import` process, a rollback will be performed by deleting (if the token user is an admin) or closing issues (otherwise) created during the `import`.

## In Unison

These scripts are meant to be used together; `gitlab.py` expects its standard input to be generated by `flyspray.py`. To extract Flyspray's database and import all of it in a single go:

    $ ./flyspray.py | ./gitlab.py -v \
        -b 'https://gitlab.server.net' \
        -t GITLAB_ACCESS_TOKEN \
        -u 'https://flyspray.server.net' \
        -a /path/to/flyspray/attachments \
        --project-mapping flyspray2gitlab.map.json \
        --default-target some/repository \
        import
