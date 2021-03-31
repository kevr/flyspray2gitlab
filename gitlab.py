#!/usr/bin/python3
#
# A script that takes flyspray.py formatted json data and imports tasks
# as issues into a GitLab instance through the user matched by a given
# GitLab access token.
#
# TODO: Add extensive formatting options to allow a user to specify
# formatting for bug task imports.
#
# License: MIT
#
# Contributions:
# Copyright (C) 2020 Kevin Morris
#
import sys
import os
import re
import argparse
import traceback
import json
import logging
import select
import requests
import pytz
import urllib
from unittest import mock
from datetime import datetime
from signal import signal, SIGPIPE, SIG_DFL
from prettytable import PrettyTable

api_base = None
tasks = []
users = dict()


def request(fn, *args, **kwargs):
    response = fn(*args, **kwargs)
    if response.status_code not in (200, 201):
        raise requests.HTTPError(
            f"GitLab API returned '{response.status_code}'.")
    return response


def api_endpoint(path):
    return '/'.join([api_base, path])


def users_endpoint():
    return '/'.join([api_base, "users"])


def user_endpoint():
    return '/'.join([api_base, "user"])


def project_endpoint(repo):
    return '/'.join([api_base, f"projects/{repo}"])


def upload_endpoint(repo):
    return '/'.join([project_endpoint(repo), "uploads"])


def issues_endpoint(repo):
    return '/'.join([project_endpoint(repo), "issues"])


def issue_endpoint(repo, issue):
    return '/'.join([issues_endpoint(repo), f"{issue}"])


def notes_endpoint(repo, issue):
    return '/'.join([issue_endpoint(repo, issue), "notes"])


def get_users(token):
    """ Retrieve a json list of users from Gitlab. """
    endpoint = users_endpoint() + f"?access_token={token}"
    response = requests.get(endpoint)
    return json.loads(response.content.decode())


def get_user(token, username):
    endpoint = users_endpoint() + f"?username={username}"
    response = requests.get(endpoint)

    data = json.loads(response.content.decode())
    if len(data):
        return data[0]


def get_user_if_missing(args, username):
    global users
    if username not in users:
        users[username] = get_user(args.token, username)
        return users.get(username)
    elif username in users:
        return users.get(username)


def error_log(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)
    return 1


def stdin_available(timeout=1):
    """ Check for timeout seconds whether stdin has available data or not. """
    result = select.select([sys.stdin.fileno()], [], [], timeout)
    return result == ([sys.stdin.fileno()], [], [])


def module_method(command):
    """ Return corresponding module method in this file for command. """
    method_string = f"command_{command}"
    if method_string not in globals():
        # Print out the error string, then return a stub function that
        # just returns 2. In short: this function can be checked against
        # 0 (success) to probe for program failure.
        print(f"error: invalid command '{command}', see --help")
        return lambda args: 2
    return globals().get(method_string)


def small_wrap(content):
    """ Wrap content in <small> tags. """
    return f"<small>{content}</small>"


def attachment_markdown(upload_result):
    """ Generate markdown for an attachment upload result. """
    parts = urllib.parse.urlparse(api_base)
    url_base = f"{parts.scheme}://{parts.netloc}"
    url = f"{url_base}{upload_result.get('path')}"
    return f"[{upload_result.get('name')}]({url})"


def attachments_markdown(attachments):
    """ Generate markdown for a list of attachments. """
    attachment_md = '<br>'.join(attachment_markdown(a) for a in attachments)
    if len(attachments) > 0:
        attachment_md = f"""\
### Attachments

{attachment_md}
"""
    return attachment_md


def upload_attachment(args, repository, attachment, root):
    """ Upload an attachment to GitLab.

    @param args The result of ArgumentParser.parse_args
    @param repository Target repository to upload the attachment to
    @param attachment An attachment dictionary generated by flyspray.py
    @param root The attachment directory

    @returns Attachment upload result dictionary
    """

    # Path to the uploaded file based on Flyspray's generated file_name.
    path = os.path.join(root, attachment.get("file_name"))

    orig_name = attachment.get("orig_name")

    files = {
        "file": (orig_name, open(path, "rb"), attachment.get("file_type"))
    }

    # And use it to upload a new file to the designated project.
    upload_ep = upload_endpoint(repository)
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {args.token}"
    }

    logging.info("Uploading attachment " +
                 f"{attachment.get('attachment_id')} to {upload_ep}.")

    response = request(requests.post, upload_ep, files=files, headers=headers)

    data = response.json()  # GitLab API response json data.
    return {"name": orig_name, "path": data.get("full_path")}


def upload_attachments(args, repository, attachments, root):
    """ Upload a list of attachments. """
    return [upload_attachment(args, repository, a, root) for a in attachments]


def raw_markdown_table(header, rows):
    """ Produce a PrettyTable for the given header and rows. """
    rows = [
        [small_wrap(e) for e in row]
        for row in rows
    ]
    table = PrettyTable(junction_char='|')
    table.field_names = header
    for row in rows:
        table.add_row(row)
    return table


def markdown_table(raw_table):
    """ Produces a markdown table out of a PrettyTable. """
    table_str = raw_table.get_string()
    return table_str[table_str.index('\n') + 1: table_str.rindex('\n')]


def get_if(fn, a, b):
    return a if fn() else b


def task_to_issue(args, task, attachments):
    user = task.get("opened_by")

    opened_by = get_if(lambda: args.upstream,
                       f"[{user.get('real_name')} ({user.get('user_name')})]"
                       f"({args.upstream}/user/{user.get('id')})",
                       f"{user.get('real_name')} ({user.get('user_name')})") \
        if not user_exists(task["opened_by"]) else \
        f"{user.get('real_name')} ({user.get('user_name')})"

    header = ["Task Info (Flyspray)", ""]

    dts = datetime.fromtimestamp(task.get("date_opened"))
    dts = dts.strftime("%Y-%m-%d %H:%M:%S UTC")
    rows = [
        ["Opened By", opened_by],
        ["Task ID", task.get("id")],
        ["Status", task.get("status")],
        ["Type", task.get("type")],
        ["Project", task.get("project")],
        ["Category", task.get("category")],
        ["Version", task.get("version")],
        ["OS", task.get("os")],
        ["Opened", dts]
    ]

    table = raw_markdown_table(header, rows)

    if task.get("closed"):
        table.add_row([
            small_wrap("Resolution"),
            small_wrap(task.get("resolution"))
        ])

    return f"""\
{markdown_table(table)}

### Details

{task.get('details')}

{attachments_markdown(attachments)}
"""


def user_exists(user):
    return user.get("user_name") in users


def comment_to_note(args, comment, attachments):
    # Links back to the user in this string may not always work. Flyspray
    # does not by default allow all users to be viewed via /user/{id} like
    # bugs.archlinux.org does.
    output = str()

    date_added = comment.get("date_added")
    date_added = datetime.fromtimestamp(date_added)

    dts = date_added.strftime("%Y-%m-%d %H:%M:%S UTC")
    output = "<small>Added %s</small>" % dts

    user = comment.get("user")
    if not get_user_if_missing(args, user.get("user_name")):
        # If the user can't be found on gitlab, reference back
        # to them via the upstream format.
        commented_by = get_if(
            lambda: args.upstream,
            f"[{user.get('real_name')} ({user.get('user_name')})]"
            f"({args.upstream}/user/{user.get('id')})",
            f"{user.get('real_name')} ({user.get('user_name')})")
        output += f"<small> - Commented by {commented_by}</small>\n\n"

    output += "\n\n"
    output += comment.get("comment_text") + "\n\n"
    output += attachments_markdown(attachments) + "\n"
    return output


def import_task(args, task, mappings):
    """ Import a single task dictionary to GitLab (provided by flyspray.py).

    @param args The result of ArgumentParser.parse_args
    @param task A task dictionary from flyspray.py
    @param mappings A dictionary of Flyspray project -> GitLab repo mappings.
    """

    # We'll add the newly imported task to this global array.
    # In case we ever error out, we'll use it to delete the tasks
    # we created if we can.
    global tasks

    gitlab_user = None

    user_name = task.get("opened_by").get("user_name").lower()
    gitlab_user = get_user_if_missing(args, user_name)

    logging.info(f"Importing task {task.get('id')}: {task.get('summary')}.")
    project = task.get("project")
    mapping = mappings.get(project, None)

    repository = args.default_target
    if mapping:
        repository = mapping
    else:
        logging.error(
            f"No mapping found for project '{project}', " +
            f"migrating to default: '{repository}'.")

    # Get repository ready to be used as :id in /project/:id.
    repository = urllib.parse.quote_plus(repository)

    issues_ep = issues_endpoint(repository)
    logging.info(f"Migrating task {task.get('id')} to {issues_ep}.")

    # Check to see if this title already exists in Gitlab.
    summary = task.get("summary")
    response = requests.get(issues_ep, params={
        "access_token": args.token,
        "search": summary
    })
    assert response.status_code == 200

    exists = len([
        i for i in json.loads(response.content.decode())
        if i.get("title") == summary
    ]) >= 1

    if args.keep_ids:
        task_id = task.get("id")
        iids = [int(task_id)]
        response = request(requests.get, issues_ep, params={
            "access_token": args.token,
            "iids": iids
        })
        _data = json.loads(response.content.decode())
        logging.error("--keep-ids was used but issue with IID already exists.")
        logging.error(
            "To continue, clear out all Gitlab issues in the target repository "
            "that match Flyspray task IDs or omit --keep-ids.")
        sys.exit(1)

    if exists:
        logging.error(
            "Issue with title '%s' already exists, skipping" % summary)
        return

    utc = pytz.timezone("UTC")
    date_opened = datetime.fromtimestamp(task["last_edited"], utc) \
        if task["last_edited"] > task["date_opened"] else \
        datetime.fromtimestamp(task["date_opened"], utc)

    attachments = []
    if not args.skip_attachments:
        attachments = task.get("attachments")
        attachments = upload_attachments(
            args, repository, attachments, args.attachments)
        logging.debug(f"Uploaded task attachments: {attachments}.")

    headers = dict()
    if gitlab_user:
        headers["Sudo"] = str(gitlab_user.get("id"))

    data = {
        "access_token": args.token,
        "title": task.get("summary"),
        "description": task_to_issue(args, task, attachments),
        "created_at": date_opened.isoformat(),
        "weight": task.get("priority_id")
    }

    if args.keep_ids:
        data["iid"] = task.get("id")

    response = request(requests.post, issues_ep, json=data, headers=headers)

    data = response.json()

    issue_id = data.get("iid")
    tasks.append((issue_id, repository))

    issue_ep = issue_endpoint(repository, issue_id)
    notes_ep = notes_endpoint(repository, issue_id)

    for comment in task.get("comments"):
        logging.info(
            f"Migrating comment {comment.get('comment_id')} to {notes_ep}.")

        _user = comment.get("user")
        _user_name = _user.get("user_name").lower()

        # This comment's gitlab user. If this variable is not None,
        # we will sudo as the user. Otherwise, we will post as
        # the token user in a slightly modified format, pointing
        # back to the originating flyspray instance.
        _gitlab_user = None

        # If the Flyspray comment's user's username is found in
        # the global gitlab users dictionary, set gitlab_user to it.
        if _user_name not in users:
            _gitlab_user = users[_user_name] = get_user(args.token, _user_name)
        elif _user_name in users:
            _gitlab_user = users.get(_user_name)

        date_added = datetime.fromtimestamp(comment["date_added"], utc)

        attachments = []
        if not args.skip_attachments:
            # Gather attachments by first uploading them to Gitlab,
            # then storing their information in attachments.
            attachments = comment.get("attachments")
            attachments = upload_attachments(
                args, repository, attachments, args.attachments)
            logging.debug(f"Uploaded comment attachments: {attachments}.")

        # At this point, attachments should be populated with any attachments
        # that were originally uploaded to Flyspray's comment.

        # Post the comment to gitlab.
        ds = date_added.isoformat() + "Z"
        ds = re.sub(r'\+\d{2}:\d{2}', '', ds)
        data = {
            "access_token": args.token,
            "body": comment_to_note(args, comment, attachments)
        }

        headers = dict()
        if _gitlab_user:
            headers["Sudo"] = str(_gitlab_user.get("id"))

        response = request(requests.post, notes_ep, json=data, headers=headers)

    if task.get("closed"):
        # Then close it by updating the issue's state to 'close'.
        request(requests.put, issue_ep, json={
            "access_token": args.token,
            "state_event": "close"
        })


def rollback(args):
    logging.warning(
        "Rolling back by deleting the issues created via HTTP API.")

    global tasks

    # Close issue
    for issue_id, repo in tasks:
        issue_endpoint = \
            f"{args.base}/api/{args.api}/projects/{repo}/issues/{issue_id}"
        response = requests.put(issue_endpoint, json={
            "access_token": args.token,
            "state_event": "close"
        })
        if response.status_code != 200:
            raise requests.HTTPError(
                f"GitLab API returned '{response.status_code}'.")

    tasks.clear()


def command_import(args, tasks):
    """ Run the import command. """

    logging.debug("Import triggered.")
    mappings = dict()
    if args.project_mapping:
        mappings = json.load(open(args.project_mapping))

    try:
        for task in tasks:
            import_task(args, task, mappings)
    except Exception:
        traceback.print_exc()
        # Perform task rollback.
        rollback(args)

    return 0


class MockResponse:
    """ A fake Response object used to return to mocked up requests. """
    data = None
    status_code = 200

    def __init__(self, data=dict()):
        self.data = data

    def json(self):
        return self.data


def command_dry(args, tasks):
    """ Run the dry command. """
    projects = [task["project"] for task in tasks]

    data = dict()

    if args.project_mapping:
        with open(args.project_mapping) as f:
            data = json.load(f)

    mappings = [
        data.get(p) if p in data else args.default_target for p in projects
    ]

    # Some variables used to maintain state during a dry run.
    # Any nested functions that alter these values must declare
    # them as nonlocal: `nonlocal c_project_id`.
    c_project_id = 0
    c_project_set = dict()

    def mock_requests(*route_args, **kwargs):
        nonlocal c_project_id
        nonlocal c_project_set

        rv = dict()

        user_ep = user_endpoint()
        rv[user_ep] = MockResponse({"is_admin": False})

        users_ep = users_endpoint()
        _users_ep = f"{users_ep}?access_token={args.token}"
        rv[_users_ep] = MockResponse()
        rv[_users_ep].content = b'[]'

        for mapping in mappings:
            repo = urllib.parse.quote_plus(mapping)

            if repo not in c_project_set:
                c_project_id += 1
                c_project_set[repo] = c_project_id

            project_id = c_project_set.get(repo)
            project_ep = project_endpoint(repo)
            if project_ep not in rv:
                rv[project_ep] = MockResponse({"id": project_id})

            upload_ep = upload_endpoint(repo)
            if upload_ep not in rv:
                rv[upload_ep] = MockResponse(
                    {"full_path": "/uploads/mocked/path"})

            # We don't really double check the issue id we get back
            # during an import, so just stub them all out as id = 1.
            issue_id = 1
            issues_ep = issues_endpoint(repo)
            if issues_ep not in rv:
                rv[issues_ep] = MockResponse({"iid": issue_id})

            issue_ep = issue_endpoint(repo, issue_id)
            if issue_ep not in rv:
                rv[issue_ep] = MockResponse()

            notes_ep = notes_endpoint(repo, issue_id)
            if notes_ep not in rv:
                rv[notes_ep] = MockResponse()

        return rv

    def mock_get(*route_args, **kwargs):
        rv = mock_requests(*route_args, **kwargs)
        return rv.get(list(route_args)[0])

    requests.get = mock.MagicMock(side_effect=mock_get)

    def mock_post(*route_args, **kwargs):
        rv = mock_requests(*route_args, **kwargs)
        return rv.get(list(route_args)[0])

    requests.post = mock.MagicMock(side_effect=mock_post)

    def mock_put(*route_args, **kwargs):
        rv = mock_requests(*route_args, **kwargs)
        return rv.get(list(route_args)[0])

    requests.put = mock.MagicMock(side_effect=mock_put)

    # Alright, all of our request endpoint mocks are setup. Run our normal
    # import command code.
    return command_import(args, tasks)


""" The following function provides a 'users' command which
generates 500 users on Gitlab. It is used purely for development.

def command_users(args, tasks):
    for i in range(500):
        response = requests.post(users_endpoint(), json={
            "access_token": args.token,
            "username": f"u{i}",
            "email": f"u{i}@example.org",
            "name": f"u{i} Master",
            "password": "password"
        })
        print(response.status_code)
        print(response.content.decode())
        assert response.status_code >= 200 and response.status_code <= 299
        logging.info(f"Created user 'u{i}' on Gitlab.")

    return 0
"""


def prepare_args():
    """ Prepare and parse arguments for the program. """
    epilog = """\
valid commands:
  import \t\timport stdin json into a gitlab instance
  dry \t\t\ta dry run of import

additional information:
  --project-mapping\ta path to a json mapping file containing project (key) to
  \t\t\trepository (value) mappings (see projects.map.json.example)
  --upstream\t\tThe upstream argument specifies an HTTP(S) base to use for
  \t\t\treferencing back to users who made the original tasks and comments
  --keep-ids\t\tpersist task ids from FLyspray over to Gitlab

Example:
  $ flyspray.py | gitlab.py import -m projects.json

Note: This program reads stdin as input for flyspray json data.
"""

    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawTextHelpFormatter(
            prog, max_help_position=80),
        usage="%(prog)s [-hv] [--skip-attachments] [-btmdua ARG] command",
        epilog=epilog)

    parser.add_argument("-v", "--verbose", default=False, const=True,
                        action="store_const", help="enable debug logging")
    parser.add_argument("-b", "--base", default="http://gitlab.local.net",
                        help="GitLab URL (default: 'http://gitlab.local.net')")
    parser.add_argument("-t", "--token", required=True,
                        help="GitLab migration user access token")
    parser.add_argument("-m", "--project-mapping",
                        help="path to a project json mapping file " +
                        "(default: 'projects.map.json')")
    parser.add_argument("-d", "--default-target", dest="default_target",
                        required=True,
                        help="default task repository")
    parser.add_argument("-u", "--upstream",
                        help="originating Flyspray server's base URL")
    parser.add_argument("-a", "--attachments", default='', required=True,
                        help="path to Flyspray attachments directory")
    parser.add_argument("--api", default="v4",
                        help="GitLab API version (default: 'v4')")
    parser.add_argument("--skip-attachments", dest="skip_attachments",
                        default=False, const=True, action="store_const",
                        help="skip attachments altogether")
    parser.add_argument("--keep-ids", default=False, const=True,
                        action="store_const",
                        help="keep task ids from Flyspray")
    parser.add_argument("command", default='',
                        help="primary command (import, dry)")
    return parser.parse_args()


def handle_args(args):
    """ Perform initialization based on our arguments. """
    level = logging.INFO
    date_fmt = "%Y-%m-%d %H:%M:%S %Z"
    fmt = "[%(levelname)5s] %(message)s"

    # If -v is provided, override a couple logging arguments.
    if args.verbose:
        level = logging.DEBUG
        fmt = "%(asctime)s [%(levelname)5s] %(message)s"

    logging.basicConfig(level=level, format=fmt, datefmt=date_fmt)
    return args


def verify_arguments(args):
    """ Make sure none of our arguments are erroneous. """
    if args.api not in {"v4", "v3"}:
        return error_log(f"invalid GitLab API version '{args.api}'")

    if not args.skip_attachments:
        if not os.path.isdir(args.attachments):
            return error_log("invalid attachments directory " +
                             f"provided: '{args.attachments}'.")
    else:
        logging.debug("Skipping attachments (--skip-attachments provided).")

    return 0


def main():
    """ The main entry point. """
    args = handle_args(prepare_args())

    bad = verify_arguments(args)
    if bad:
        return bad

    global api_base
    api_base = f"{args.base}/api/{args.api}"

    # Process stdin into a json list of task objects.
    if not stdin_available():
        return error_log(
            "Timed out waiting for stdin; input JSON is required.")

    stdin = sys.stdin.read()
    tasks = json.loads(stdin)

    method = module_method(args.command)
    return method(args, tasks)


if __name__ == "__main__":
    # Used signal(..., ...) in flyspray.py to suppress false warnings,
    # did it here in case someone ever piped gitlab.py to somewhere
    # else in the same manner.
    signal(SIGPIPE, SIG_DFL)
    e = 1
    try:
        e = main()
    except NotImplementedError as exc:
        print(f"error: {exc}")
    except Exception:
        traceback.print_exc()
    sys.exit(e)
