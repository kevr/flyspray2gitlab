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
import urllib
from datetime import datetime, timezone
from signal import signal, SIGPIPE, SIG_DFL
from prettytable import PrettyTable

api_base = None

gitlab_users = dict()
gitlab_members = dict()

to_restore = dict()
to_remove = set()

email_settings = dict()

repositories = set()

dependencies = dict()

tasks = list()

username_mapping = dict()


def request(fn, *args, **kwargs):
    response = fn(*args, **kwargs)
    if response.status_code not in (200, 201, 204):
        logging.error(response.content.decode())
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
    return '/'.join([api_base, "projects", repo])


def upload_endpoint(repo):
    return '/'.join([project_endpoint(repo), "uploads"])


def issues_endpoint(repo):
    return '/'.join([project_endpoint(repo), "issues"])


def issue_endpoint(repo, issue):
    return '/'.join([issues_endpoint(repo), str(issue)])


def issue_links_endpoint(repo, issue):
    return '/'.join([issue_endpoint(repo, issue), "links"])


def notes_endpoint(repo, issue):
    return '/'.join([issue_endpoint(repo, issue), "notes"])


def groups_endpoint():
    return '/'.join([api_base, "groups"])


def group_endpoint(group):
    return '/'.join([groups_endpoint(), group])


def members_endpoint(group):
    return '/'.join([group_endpoint(group), "members"])


def member_endpoint(group, user):
    return '/'.join([group_endpoint(group), "members", str(user.get("id"))])


def disable_email(token, path):
    global email_settings
    endpoint = project_endpoint(path)
    response = request(requests.get, endpoint, {
        "access_token": token
    })
    data = json.loads(response.content.decode())
    email_settings[path] = data.get("emails_disabled")

    if not email_settings.get(path):
        return request(requests.put, endpoint, json={
            "access_token": token,
            "emails_disabled": True
        })


def restore_email(token, path, mode):
    global email_settings
    endpoint = project_endpoint(path)
    if path in email_settings:
        return request(requests.put, endpoint, json={
            "access_token": token,
            "emails_disabled": mode
        })


def restore_emails(token):
    global email_settings
    for path, on in email_settings.items():
        restore_email(token, path, on)


def get_users(token):
    """ Retrieve a json list of users from Gitlab. """
    endpoint = users_endpoint() + f"?access_token={token}"
    response = requests.get(endpoint)
    return json.loads(response.content.decode())


def get_user(token, username):
    global gitlab_users

    if username in username_mapping:
        username = username_mapping.get(username).lower()

    if username not in gitlab_users:
        endpoint = users_endpoint() + f"?username={username}"
        response = requests.get(endpoint)

        data = json.loads(response.content.decode())
        if len(data):
            gitlab_users[username] = data[0]

    return gitlab_users.get(username, None)


def get_member(token, group, username):
    global gitlab_members

    key = f"{group}--{username}"
    if key not in gitlab_members:
        user = get_user(token, username)
        ids = []
        if user:
            ids.append(int(user.get("id")))

        response = requests.get(members_endpoint(group), params={
            "access_token": token,
            "user_ids": ids
        })

        if response.status_code != 404:
            data = json.loads(response.content.decode())
            if len(data):
                gitlab_members[key] = data[0]

    return gitlab_members.get(key, None)


def get_issue(token, group, iid):
    endpoint = issue_endpoint(group, iid)
    response = request(requests.get, endpoint, params={
        "access_token": token
    })
    return json.loads(response.content.decode())


def apply_dependencies(args, mappings, tasks, issues):
    logging.info("Applying dependencies...")

    for task in tasks:
        project = task.get("project")
        repo = mappings.get(project, args.default_target)

        task_id = task.get("id")
        user = task.get("opened_by")

        headers = dict()
        gitlab_user = get_user(args.token, user.get("user_name").lower())
        if gitlab_user:
            headers["Sudo"] = str(gitlab_user.get("id"))

        quoted_repo = urllib.parse.quote_plus(repo)
        issue = issues.get(str(task_id))
        endpoint = issue_links_endpoint(quoted_repo, str(issue.get("iid")))

        for dep in task.get("dependencies"):
            data = {
                "access_token": args.token,
                "target_project_id": repo,
                "target_issue_iid": issues.get(str(dep)).get("iid"),
                # A 'link_type' of 'relates_to' is used here in our request.
                # We want to use 'blocks' or 'is_blocked_by', however, when
                # sending requests with those link_types, Gitlab returns
                # successfully and creates an issue relationship with a
                # 'relates_to' type.
                "link_type": "relates_to"
            }

            logging.info(
                "Issue titled '%s' relates to '%s', applying relationship." % (
                    issues.get(str(task_id)).get("title"),
                    issues.get(str(dep)).get("title")
                )
            )
            request(requests.post, endpoint, json=data, headers=headers)


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


def upload_attachment(args, repository, user, attachment, root):
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
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {args.token}"
    }

    if user:
        headers["Sudo"] = str(user.get("id"))

    upload_ep = upload_endpoint(repository)

    logging.info("Uploading attachment " +
                 f"{attachment.get('attachment_id')} to {upload_ep}.")

    response = request(requests.post, upload_ep, files=files, headers=headers)

    data = response.json()  # GitLab API response json data.
    return {"name": orig_name, "path": data.get("full_path")}


def upload_attachments(args, repository, user, attachments, root):
    """ Upload a list of attachments. """
    return [
        upload_attachment(args, repository, user, a, root)
        for a in attachments
    ]


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

    opened_by_username = task.get("opened_by").get("user_name").lower()
    opened_by = get_if(lambda: args.upstream,
                       f"[{user.get('real_name')} ({user.get('user_name')})]"
                       f"({args.upstream}/user/{user.get('id')})",
                       f"{user.get('real_name')} ({user.get('user_name')})") \
        if not get_user(args.token, opened_by_username) else \
        f"{user.get('real_name')} ({user.get('user_name')})"

    header = ["Task Info (Flyspray)", ""]

    dts = make_datetime(task.get("date_opened"))
    rows = [
        ["Opened By", opened_by],
        ["Task ID", task.get("id")],
        ["Type", task.get("type")],
        ["Project", task.get("project")],
        ["Category", task.get("category")],
        ["Version", task.get("version")],
        ["OS", task.get("os")],
        ["Opened", dts.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Status", task.get("status")],
    ]

    if task.get("assignee") and not get_user(args.token,
                                             task.get("assignee")
                                             .get("user_name")
                                             .lower()):
        # In this case, there is no assigned user to the Gitlab issue.
        # Back-reference to the original user @ upstream.
        assignee = task.get("assignee")
        text = get_if(lambda: args.upstream,
                      f"[{assignee.get('real_name')} "
                      f"({assignee.get('user_name')})]"
                      f"({args.upstream}/user/{assignee.get('id')})",
                      f"{assignee.get('real_name')} "
                      f"({assignee.get('user_name')})")
        rows.append(["Assignee", text])

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


def close_comment(args, task, group_owned=False):
    output = str()

    if not group_owned:
        date_closed = make_datetime(task.get("date_closed"))
        dts = date_closed.strftime("%Y-%m-%d %H:%M:%S UTC")
        output += "<small>Added %s</small>" % dts

    user = task.get("closed_by")
    if not get_user(args.token, user.get("user_name").lower()):
        commented_by = get_if(
            lambda: args.upstream,
            f"[{user.get('name')} ({user.get('username')})]"
            f"({args.upstream}/user/{user.get('id')})",
            f"{user.get('name')} ({user.get('username')})")
        if not group_owned:
            output += "<small> - </small>"
        output += f"<small>Commented by {commented_by}</small>\n\n"

    comment = task.get("closure_comment")
    output += "\n\n**Additional comments about closing**\n\n" + comment + "\n"
    return output


def comment_to_note(args, comment, attachments, group_owned=False):
    # Links back to the user in this string may not always work. Flyspray
    # does not by default allow all users to be viewed via /user/{id} like
    # bugs.archlinux.org does.
    output = str()

    if not group_owned:
        date_added = make_datetime(comment.get("date_added"))
        dts = date_added.strftime("%Y-%m-%d %H:%M:%S UTC")
        output += "<small>Added %s</small>" % dts

    user = comment.get("user")
    if not get_user(args.token, user.get("user_name").lower()):
        # If the user can't be found on gitlab, reference back
        # to them via the upstream format.
        commented_by = get_if(
            lambda: args.upstream,
            f"[{user.get('real_name')} ({user.get('user_name')})]"
            f"({args.upstream}/user/{user.get('id')})",
            f"{user.get('real_name')} ({user.get('user_name')})")
        if not group_owned:
            output += "<small> - </small>"
        output += f"<small>Commented by {commented_by}</small>\n\n"

    output += "\n\n"
    output += comment.get("comment_text") + "\n\n"
    output += attachments_markdown(attachments) + "\n"
    return output


class Memory(dict):
    def __hash__(self):
        return self.get("id")

    def __eq__(self, o):
        return self.get("id") == o.get("id")


def promote(token, repository, group, is_group, user, member):
    if not is_group:
        return

    global to_restore
    global to_remove
    global repositories

    repositories.add((repository, group, is_group))

    if member:
        # Only change the member's level if it's not 40 yet.
        if member.get("access_level") != 50:
            to_restore[Memory(user)] = member.get("access_level")
            request(requests.put, member_endpoint(group, user), json={
                "access_token": token,
                "access_level": 50  # Maintainer
            })
            logging.info(f"Updated {user.get('username')} to maintainer")
    else:
        to_remove.add(Memory(user))
        request(requests.post, members_endpoint(group), json={
            "access_token": token,
            "user_id": user.get("id"),
            "access_level": 50  # Maintainer
        })
        logging.info(f"Added {user.get('username')} as project member")


def restore(token, repository, group, is_group):
    global to_restore
    global to_remove
    global email_settings

    if not is_group:
        return

    if len(to_restore):
        logging.info("Restoring access levels to those updated...")

    for user, access_level in to_restore.items():
        request(requests.put, member_endpoint(group, user), json={
            "access_token": token,
            "access_level": access_level
        })
        logging.info(f"Reverted {user.get('username')} to {access_level}.")
    to_restore = dict()

    users_to_remove = list(to_remove)
    if len(users_to_remove):
        logging.info("Removing users we added...")

    for user in users_to_remove:
        request(requests.delete, member_endpoint(group, user), json={
            "access_token": token
        })
        logging.info(f"Removed {user.get('username')} from the project.")
    to_remove = set()

    if len(email_settings):
        logging.info("Restoring email settings we updated...")

    restore_emails(token)
    email_settings = dict()


def import_comments(args, to_restore, to_remove, task, issue, repo, group,
                    is_group, mappings):
    notes_ep = notes_endpoint(repo, issue.get("iid"))
    for comment in task.get("comments"):
        logging.info(
            f"Migrating comment {comment.get('comment_id')} to {notes_ep}.")

        _user = comment.get("user")
        _user_name = _user.get("user_name").lower()

        _gitlab_user = get_user(args.token, _user_name)
        _gitlab_member = get_member(args.token, group, _user_name)
        promote(args.token, repo, group, is_group,
                _gitlab_user, _gitlab_member)

        # This comment's gitlab user. If this variable is not None,
        # we will sudo as the user. Otherwise, we will post as
        # the token user in a slightly modified format, pointing
        # back to the originating flyspray instance.
        _gitlab_user = None

        # If the Flyspray comment's user's username is found in
        # the global gitlab users dictionary, set gitlab_user to it.
        if _user_name not in gitlab_users:
            _gitlab_user = get_user(args.token, _user_name)
        else:
            _gitlab_user = gitlab_users.get(_user_name)

        date_added = make_datetime(comment.get("date_added"))

        attachments = []
        if not args.skip_attachments:
            # Gather attachments by first uploading them to Gitlab,
            # then storing their information in attachments.
            attachments = comment.get("attachments")
            attachments = upload_attachments(
                args, repo, _gitlab_user, attachments, args.attachments)
            logging.debug(f"Uploaded comment attachments: {attachments}.")

        # At this point, attachments should be populated with any attachments
        # that were originally uploaded to Flyspray's comment.

        # Post the comment to gitlab.
        _data = {
            "access_token": args.token,
            "body": comment_to_note(args, comment, attachments, is_group)
        }

        if is_group:
            _data["created_at"] = make_gitlab_time(date_added)

        headers = dict()
        if _gitlab_user:
            headers["Sudo"] = str(_gitlab_user.get("id"))

        request(requests.post, notes_ep,
                json=_data, headers=headers)


def make_datetime(timestamp):
    return datetime.fromtimestamp(timestamp).astimezone(timezone.utc)


def make_gitlab_time(datetime):
    string = datetime.astimezone(timezone.utc).isoformat() + "Z"
    return re.sub(r'\+\d{2}:\d{2}', '', string)


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
    global to_restore
    global to_remove

    # Task-opening username.
    user_name = task.get("opened_by").get("user_name").lower()

    # Gitlab user, if it exists. If it does not, None.
    gitlab_user = get_user(args.token, user_name)

    logging.info(f"Importing task {task.get('id')}: {task.get('summary')}.")
    project = task.get("project")  # Flyspray project name.

    # Take our given --default-target or project mapping provided
    # via -m (--project-mappings).
    repository = mappings.get(project, args.default_target)
    logging.info(f"Resolved target '{repository}' for '{project}'.")

    # Extract  the 'group' part of our target repository.
    # Example: 'group/project'
    group = repository.split('/')[0]

    # Get repository ready to be used as :id in /project/:id.
    repository = urllib.parse.quote_plus(repository)

    response = request(requests.get, groups_endpoint(), {
        "access_token": args.token,
        "search": group
    })

    # Is this target a repository inside of a group?
    is_group = len(json.loads(response.content.decode())) >= 1 and args.promote

    gitlab_member = get_member(args.token, group, user_name)
    promote(args.token, repository, group,
            is_group, gitlab_user, gitlab_member)

    issues_ep = issues_endpoint(repository)
    logging.info(f"Migrating task {task.get('id')} to {issues_ep}.")

    # Check to see if this title already exists in Gitlab.
    summary = task.get("summary")
    response = request(requests.get, issues_ep, params={
        "access_token": args.token,
        "search": summary
    })

    if args.keep_ids:
        # Make sure that no issue with the id exists.
        task_id = task.get("id")
        iids = [int(task_id)]
        response = request(requests.get, issues_ep, params={
            "access_token": args.token,
            "iids": iids
        })
        _data = json.loads(response.content.decode())
        if len(_data) >= 1:
            restore(args.token, repository, group, is_group)
            raise Exception("--keep-ids was used but an issue with "
                            f"task id '{task_id}' exists. To continue, remove "
                            "the offending Gitlab issue in the target "
                            "repository. Offending issue location: "
                            f"{_data[0].get('_links').get('self')}.")

    issues = [
        i for i in json.loads(response.content.decode())
        if i.get("title") == summary
    ]
    exists = len(issues) >= 1

    if exists:
        # NOTE: Bug! If we return an already created issue here,
        # we will end up reprocessing it for dependencies.
        logging.error(
            "Issue with title '%s' already exists, skipping." % summary)
        return issues[0]

    date_opened = make_datetime(task.get("date_opened"))

    attachments = []
    if not args.skip_attachments:
        attachments = task.get("attachments")
        attachments = upload_attachments(
            args, repository, gitlab_user, attachments, args.attachments)
        logging.debug(f"Uploaded task attachments: {attachments}.")

    headers = dict()
    if gitlab_user:
        headers["Sudo"] = str(gitlab_user.get("id"))

    assignees = []
    if task.get("assignee"):
        _gitlab_user = get_user(args.token,
                                task.get("assignee").get("user_name").lower())
        if _gitlab_user:
            assignees.append(_gitlab_user.get("id"))

    data = {
        "access_token": args.token,
        "title": task.get("summary"),
        "description": task_to_issue(args, task, attachments),
        "created_at": make_gitlab_time(date_opened),
        "weight": task.get("priority_id"),
        "confidential": bool(task.get("mark_private")),
        "assignee_ids": assignees
    }

    if args.keep_ids:
        data["iid"] = task.get("id")

    # Disable notifications on this project.
    disable_email(args.token, repository)

    response = request(requests.post, issues_ep, json=data, headers=headers)

    data = response.json()

    issue_id = data.get("iid")
    tasks.append((issue_id, repository))

    issue_ep = issue_endpoint(repository, issue_id)
    notes_ep = notes_endpoint(repository, issue_id)

    import_comments(args, to_restore, to_remove, task, data,
                    repository, group, is_group, mappings)

    date_closed = make_datetime(task.get("date_closed"))
    if task.get("closed"):
        closed_by = task.get("closed_by")
        _user = get_user(args.token, closed_by.get("user_name"))
        closed_by_member = get_member(args.token, group,
                                      closed_by.get("username"))

        promote(args.token, repository, group, is_group,
                closed_by, closed_by_member)
        if task.get("closure_comment"):
            _data = {
                "access_token": args.token,
                "body": close_comment(args, task, is_group)
            }

            if is_group:
                _data["created_at"] = make_gitlab_time(date_closed)

            headers = {
                "Sudo": str(_user.get("id"))
            }

            # Add closure comment note.
            response = request(requests.post, notes_ep,
                               json=_data, headers=headers)

        headers = dict()
        if get_user(args.token, _user.get("username").lower()):
            headers["Sudo"] = str(_user.get("id"))

        # Then close it by updating the issue's state to 'close'.
        request(requests.put, issue_ep, json={
            "access_token": args.token,
            "updated_at": make_gitlab_time(date_closed),
            "state_event": "close"
        }, headers=headers)

    # Restore repository members.
    restore(args.token, repository, group, is_group)

    return data


def rollback(args):
    logging.warning(
        "Rolling back by deleting the issues created via HTTP API.")

    global tasks

    # Close issue.
    for issue_id, repo in tasks:
        logging.info("Removing issue with ID '%s'." % issue_id)
        issue_ep = issue_endpoint(repo, issue_id)
        request(requests.delete, issue_ep, json={
            "access_token": args.token
        })
        logging.info("Removed issue with ID '%s'." % issue_id)

    tasks.clear()


def restore_all(token):
    global repositories
    for repo, group, is_group in repositories:
        restore(token, repo, group, is_group)
    repositories = set()


def command_import(args, tasks):
    """ Run the import command. """
    global repositories

    logging.debug("Import triggered.")
    mappings = dict()
    if args.project_mapping:
        mappings = json.load(open(args.project_mapping))

    # A mapping of flyspray task ids to gitlab issue ids.
    # This mapping can be used to match tasks for redirection purposes.
    iid_mapping = dict()
    issues = dict()

    i = 0
    while i < len(tasks):
        task = tasks[i]
        project = task.get("project")
        repo = mappings.get(project, args.default_target)

        try:
            issue = import_task(args, task, mappings)
            issues[str(task.get("id"))] = issue
        except (Exception, KeyboardInterrupt):
            restore_all(args.token)

            traceback.print_exc()
            logging.info("We encountered a fatal exception. You have the "
                         "following options: (R)etry, (n)ext, and (q)uit.")
            logging.info("")
            logging.info(" - Retry: Try the failed task again.")
            logging.info(" - Next: Move on to the next task and continue.")
            logging.info(" - Quit: Quit the migration.")
            logging.info("")

            try:
                choice = input("Choice (R/n/q): ")
            except (Exception, KeyboardInterrupt):
                logging.error(
                    "Caught another exception during input, rolling back.")
                rollback(args)
                restore_all(args.token)
                return 1
            if not choice or choice.lower() == 'r':
                continue
            elif choice.lower() == 'n':
                i += 1
                continue
            elif choice.lower() == 'q':
                logging.info("Rolling back...")
                rollback(args)
                restore_all(args.token)
                logging.info("Good bye!")
                return 0

        if args.id_mapping_output:
            # Populate iid_mapping with this task.
            task_id = str(task.get("id"))
            if task_id not in iid_mapping:
                repo_ep = '/'.join([args.base, repo])
                repo_ep += f"/issues/{issue.get('iid')}"
                iid_mapping[task_id] = repo_ep
        i += 1

    apply_dependencies(args, mappings, tasks, issues)

    if args.id_mapping_output:
        with open(args.id_mapping_output, "w") as fh:
            json.dump(iid_mapping, fh, indent=2)
        logging.info(
            "Dumped ID mappings to JSON file '%s'." % args.id_mapping_output)

    return 0


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

additional information:
  --project-mapping\ta path to a json mapping file containing project (key) to
  \t\t\trepository (value) mappings (see projects.map.json.example)
  --upstream\t\tThe upstream argument specifies an HTTP(S) base to use for
  \t\t\treferencing back to users who made the original tasks and comments
  --keep-ids\t\tpersist task ids from FLyspray over to Gitlab
  --id-mapping-output\ta writable path to a json mapping output file of
  \t\t\tFlyspray task ids to Gitlab issue URLs
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
    parser.add_argument("--id-mapping-output",
                        help="task id to issue url mapping output file")
    parser.add_argument("-f", "--dump-file", required=True, help="dump file")
    parser.add_argument("--promote", default=False, action="store_const",
                        const=True, help="enable owner promotion")
    username_help = "path to json mapping of Flyspray to Gitlab usernames"
    parser.add_argument("--username-mapping", help=username_help)
    parser.add_argument("command", default='',
                        help="primary command (import)")

    args = parser.parse_args()

    global username_mapping
    username_mapping = dict()

    if args.username_mapping:
        with open(args.username_mapping) as f:
            username_mapping = json.load(f)

    # Lowercase all the keys.
    lower_keys = dict()
    to_delete = list()

    for k, v in username_mapping.items():
        lower_k = k.lower()
        if lower_k not in username_mapping:
            lower_keys[lower_k] = v
            to_delete.append(k)

    for k, v in lower_keys.items():
        username_mapping[k] = v

    for k in to_delete:
        del username_mapping[k]

    return args


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
    try:
        with open(args.dump_file) as fh:
            stdin = fh.read()
    except OSError:
        return error_log("No dump file could be read.")

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
