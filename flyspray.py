#!/usr/bin/python3
#
# A script that extracts Flyspray bug task data out of Flyspray's
# MySQL database and outputs it in a flyspray.py-specific JSON format.
#
# License: MIT
#
# Contributions:
# Copyright (C) 2020 Kevin Morris
#
import sys
import pymysql
import psycopg2
import json
import argparse
import traceback
import re
from signal import signal, SIGPIPE, SIG_DFL

connection = None
prefix = "flyspray_"


def pg_connect(host, port, user, password, db):
    return psycopg2.connect(host=host, port=port,
                            user=user, password=password,
                            dbname=db)


def my_connect(host, port, user, password, db):
    return pymysql.connect(host=host, port=port,
                           user=user, password=password,
                           db=db, charset="utf8")


DB_CONNECTORS = {
    "pgsql": pg_connect,
    "mysql": my_connect
}


def connect(db_type, host, port, user, password, db):
    """ Configure the global connection object with pymysql.

    @param host MySQL host
    @param port MySQL port
    @param user MySQL user
    @param password MySQL password
    @param db MySQL database name
    @returns Global connection object
    """
    global connection
    _connect = DB_CONNECTORS.get(db_type)
    connection = _connect(host, port, user, password, db)
    return connection


def show_tables():
    """ Convenient fetching of our database tables. """
    with connection.cursor() as cursor:
        sql = "SHOW TABLES"
        cursor.execute(sql)
        result = [row[0] for row in cursor.fetchall()]
        return result


def describe_table(database, prefix, table):
    """ Execute a DESCRIBE statement on a table and return the results. """
    with connection.cursor() as cursor:
        sql = f"SELECT * FROM {prefix}{table} LIMIT 0"
        cursor.execute(sql)
        result = [(row[0], row[1]) for row in cursor.description]
        return result


def parse_tags(summary):
    """ Parse tags out of a summary.

    bugs.archlinux.org uses summary tags to denote which packages are being
    mentioned in a task report. This is included in the form of:

    "[tag1] [tag2] [...] Summary Text"

    @param summary A task summary
    @returns List of tags found in summary
    """
    return re.findall(r'\[([^\]]+)\]', summary)


def task_query(args, database, prefix):
    """ Return SQL used to fetch all tasks from Flyspray's DB. """
    where = str()
    if args.project_id:
        where = f"WHERE t.project_id={args.project_id}"
    return f"""
SELECT
t.task_id,
tt.tasktype_name,
cat.category_name,
p.project_title,
t.item_summary,
t.detailed_desc,
u.user_id,
t.task_priority,
ls.status_name,
t.date_opened,
t.last_edited_time,
au.user_id,
t.is_closed,
lr.resolution_name,
lv.version_name,
os.os_name,
t.closed_by,
t.closure_comment,
t.date_closed,
t.mark_private
FROM {prefix}tasks t
LEFT OUTER JOIN {prefix}users u ON u.user_id = t.opened_by
LEFT OUTER JOIN {prefix}assigned a ON a.task_id = t.task_id
LEFT OUTER JOIN {prefix}users au ON au.user_id = a.user_id
LEFT OUTER JOIN {prefix}list_os os ON os.os_id = t.operating_system
LEFT OUTER JOIN {prefix}projects p ON p.project_id = t.project_id
LEFT OUTER JOIN {prefix}list_tasktype tt ON tt.tasktype_id = t.task_type
LEFT OUTER JOIN {prefix}list_category cat ON
cat.category_id = t.product_category
LEFT OUTER JOIN {prefix}list_status ls ON ls.status_id = t.item_status
LEFT OUTER JOIN {prefix}list_resolution lr ON
lr.resolution_id = t.resolution_reason
LEFT OUTER JOIN {prefix}list_version lv ON lv.version_id = t.product_version
{where}
GROUP BY tt.tasktype_name, cat.category_name, t.task_id, a.task_id,
p.project_title, u.user_id, ls.status_name, au.user_id, lr.resolution_name,
lv.version_name, os.os_name
"""


def dependencies_query(where=str()):
    return f"SELECT task_id, dep_task_id FROM {prefix}dependencies {where}"


def get_dependencies(task):
    sql = dependencies_query("WHERE task_id = %s")
    return execute(sql, task.get("id"))


def execute(*args, **kwargs):
    with connection.cursor() as cursor:
        cursor.execute(*args, **kwargs)
        return cursor.fetchall()


def task_convert(task, users=dict()):
    """ Convert a result of task_query() to Python dictionary. """
    return {
        "id": task[0],
        "type": task[1],
        "category": task[2],
        "project": task[3],
        "summary": task[4],
        "details": task[5],
        "opened_by": task[6],
        "priority_id": task[7],
        "status": task[8],
        "date_opened": task[9],
        "last_edited": task[10],
        "assigned": task[11],
        "closed": bool(task[12]),
        "resolution": task[13],
        "version": task[14],
        "os": task[15],
        "closed_by": task[16],
        "closure_comment": task[17],
        "date_closed": task[18],
        "mark_private": task[19],

        # Some extra customized fields.
        "tags": parse_tags(task[4])
    }


def user_middleware(prefix, user):
    return user


def task_middleware(prefix, task):
    task["assignees"] = list()
    with connection.cursor() as cursor:
        sql = f"""
SELECT task_id, user_id FROM {prefix}assigned
WHERE task_id = %s
"""
        cursor.execute(sql, args=[task.get("id")])
        results = cursor.fetchall()

    for result in results:
        task_id, user_id = result
        sql = user_query(None, None, prefix, "WHERE user_id = %s")
        with connection.cursor() as cursor:
            cursor.execute(sql, args=[user_id])
            result = cursor.fetchone()

        task["assignees"].append(user_convert(result))

    task["dependencies"] = [dep[1] for dep in get_dependencies(task)]
    return task


def task_attachments(database, prefix, task):
    """ Fetch attachments related to a task returned by task_convert. """
    sql = f"""SELECT
a.attachment_id,
a.task_id,
a.comment_id,
a.orig_name,
a.file_name,
a.file_type,
a.file_size,
a.added_by,
a.date_added
FROM {prefix}attachments a
WHERE task_id = {task['id']}
"""

    results = []
    with connection.cursor() as cursor:
        cursor.execute(sql)
        results = list(cursor.fetchall())

    return [
        {
            "attachment_id": r[0],
            "task_id": r[1],
            "comment_id": r[2],
            "orig_name": r[3],
            "file_name": r[4],
            "file_type": r[5],
            "file_size": r[6],
            "date_added": r[8]
        } for r in results
    ]


def task_finalize(database, prefix, task, users=dict()):
    """ Perform final operations on a task after task_convert is run. """

    # Get comments
    sql = f"""SELECT * FROM {prefix}comments c
WHERE task_id = {task['id']}
"""

    results = []
    with connection.cursor() as cursor:
        cursor.execute(sql)
        results = list(cursor.fetchall())

    # We need to explicitly create our own user dict out of this
    # query so we can delete keys ourselves.
    user = users.get(task["opened_by"])

    if user:
        task["opened_by"] = user

    attachments = {
        a["comment_id"]: a
        for a in task_attachments(database, prefix, task)
    }

    task["attachments"] = list(
        filter(lambda a: a["comment_id"] == 0, attachments.values()))
    task["comments"] = []
    description = describe_table(database, prefix, "comments")
    for result in results:
        d = dict()
        for i in range(len(description)):
            key = description[i][0]
            value = result[i]
            d[key] = value

        user_id = d.get("user_id")
        d["user"] = users.get(user_id)

        # Remove passwords from the user dicts we construct here.
        if "user_pass" in d["user"]:
            del d["user"]["user_pass"]

        del d["user_id"]

        d["attachments"] = list(
            filter(lambda a: a["comment_id"] == d["comment_id"],
                   attachments.values()))
        task["comments"].append(d)

    closed_by = task.get("closed_by")
    if closed_by is not None:
        task["closed_by"] = users.get(closed_by)

    return task


def user_query(args, database, prefix, where=str()):
    """ Return SQL used to fetch a user from Flyspray's DB. """
    return f"""SELECT user_id, user_name, real_name, email_address,
account_enabled, dateformat, dateformat_extended, magic_url,
register_date, time_zone
FROM {prefix}users
{where}
"""


def user_convert(user):
    """ Convert the result of user_query() to Python dictionary. """
    return {
        "id": user[0],
        "user_name": user[1],
        "real_name": user[2],
        "email_address": user[3],
        "account_enabled": bool(user[4]),
        "dateformat": user[5],
        "dateformat_extended": user[6],
        "magic_url": user[7],
        "register_date": user[8],
        "time_zone": user[9]
    }


def user_finalize(database, prefix, user):
    """ Perform final operations on a user after task_convert is run. """
    return user


def get_target(nargs, database, prefix, table, *args):

    # Some query for different tables
    criterion = {
        "users": user_query,
        "tasks": task_query
    }

    converters = {
        "users": user_convert,
        "tasks": task_convert
    }

    middlewares = {
        "users": user_middleware,
        "tasks": task_middleware
    }

    destructors = {
        "users": user_finalize,
        "tasks": task_finalize
    }

    if table not in criterion:
        raise KeyError(f"no target '{table}' found")

    f = criterion.get(table)
    convert = converters.get(table)
    destructor = destructors.get(table)
    middleware = middlewares.get(table)

    sql = f(nargs, database, prefix)
    with connection.cursor() as cursor:
        cursor.execute(sql)
        results = cursor.fetchall()
        return [
            destructor(database, prefix,
                       middleware(prefix, convert(result)), *args)
            for result in results
        ]


def main():
    """ Main entry point. """
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawTextHelpFormatter(
            prog, max_help_position=80))
    parser.add_argument("--host", dest="host", default="localhost",
                        help="db server host (default: 'localhost')")
    parser.add_argument("--port", dest="port", default=3306, type=int,
                        help="db server port (default: 3306)")
    parser.add_argument("--user", dest="user", default="flyspray",
                        help="db user (default: 'flyspray')")
    parser.add_argument("--password", dest="password", default="flyspray",
                        help="db password (default: 'flyspray')")
    parser.add_argument("--db-type", dest="db_type", default="pgsql",
                        help="database type: (mysql|pgsql)")
    parser.add_argument("--database", dest="database", default="flyspray",
                        help="db name (default: 'flyspray')")
    parser.add_argument("--prefix", dest="prefix", default="flyspray_",
                        help="database table prefix (default: 'flyspray_')")
    parser.add_argument("--project-id", dest="project_id",
                        help="specific project id (optional)")
    args = parser.parse_args()

    global prefix
    prefix = args.prefix

    try:
        connect(args.db_type, args.host, args.port,
                args.user, args.password, args.database)
    except Exception as exc:
        print(f"error: {str(exc)}")
        return 1

    # print(describe_table(args.database, args.prefix, "users"))
    # print(describe_table(args.database, args.prefix, "assigned"))
    users = get_target(args, args.database, args.prefix, "users")
    tasks = get_target(args, args.database, args.prefix, "tasks",
                       {u["id"]: u for u in users})

    unique = dict()
    for i in range(len(tasks)):
        task = tasks[i]
        task_id = task.get("id")
        if task_id not in unique:
            unique[task_id] = task
        else:
            # This is hella nasty. We are nesting so hard. Make some
            # helper functions for this, you lazy bum!
            for assignee in task.get("assignees"):
                assignee_id = assignee.get("id")
                deduped = list(filter(lambda a: a.get("id") != assignee_id,
                                      task.get("assignees")))
                for assignee in deduped:
                    unique[task_id]["assignees"].append(assignee)

    print(json.dumps(list(unique.values()), indent=2), end='')
    return 0


if __name__ == "__main__":
    # signal(SIGPIPE, SIG_DL) ignores SIGPIPE, which causes this script
    # to output a warning message via logging.py.
    signal(SIGPIPE, SIG_DFL)  # no-op SIGPIPE
    e = 1
    try:
        e = main()
    except Exception:
        traceback.print_exc()
    sys.exit(e)
