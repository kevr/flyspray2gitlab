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
import argparse
import traceback
import json
import logging
import select
import requests
import pytz
import urllib
from datetime import datetime
from signal import signal, SIGPIPE, SIG_DFL
from prettytable import PrettyTable

api_base = None
tasks = []

def api_endpoint(path):
  return f"{api_base}{path}"

def error_log(*args, **kwargs):
  print(*args, **kwargs, file=sys.stderr)
  return 1

def stdin_available(timeout=1):
  """ Check for timeout seconds whether stdin has available data or not. """
  result = select.select([sys.stdin.fileno()], [], [], timeout)
  return result == ([sys.stdin.fileno()], [], [])

def summary_to_title(summary):
  return summary

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
    "file": ( orig_name, open(path, "rb"), attachment.get("file_type") )
  }

  # And use it to upload a new file to the designated project.
  upload_endpoint = f"{api_base}/projects/{repository}/uploads"
  headers = {
    "Accept": "application/json",
    "Authorization": f"Bearer {args.token}"
  }

  logging.info("Uploading attachment " +
      f"{attachment.get('attachment_id')} to {upload_endpoint}.")
  response = requests.post(upload_endpoint, files=files, headers=headers)

  if not response.status_code in (200, 201):
    raise requests.HTTPError(f"GitLab API returned '{response.status_code}'.")

  data = response.json() # GitLab API response json data.
  return { "name": orig_name, "path": data.get("full_path") }

def upload_attachments(args, repository, attachments, root):
  """ Upload a list of attachments. """
  return [ upload_attachment(args, repository, a, root) for a in attachments ]

def small_wrap(content):
  """ Wrap content in <small> tags. """
  return f"<small>{content}</small>"

def raw_markdown_table(header, rows):
  """ Produce a PrettyTable for the given header and rows. """
  rows = [
    [ small_wrap(e) for e in row ]
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
  return table_str[table_str.index('\n') + 1 : table_str.rindex('\n')]

def get_if(fn, a, b):
  if fn():
    return a
  return b

def task_to_issue(args, task, attachments):
  user = task.get("opened_by")

  opened_by = get_if(lambda: args.upstream,
      f"[{user.get('real_name')} ({user.get('user_name')})]" \
      f"({args.upstream}/user/{user.get('id')})",
      f"{user.get('real_name')} ({user.get('user_name')})")

  header = ["Task Info (Flyspray)", ""]
  rows = [
    [ "Opened By", opened_by ],
    [ "Task ID", task.get("id") ],
    [ "Status", task.get("status") ],
    [ "Type", task.get("type") ],
    [ "Project", task.get("project") ],
    [ "Category", task.get("category") ],
    [ "Version", task.get("version") ],
    [ "OS", task.get("os") ],
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

def comment_to_note(args, comment, attachments):
  # Links back to the user in this string may not always work. Flyspray
  # does not by default allow all users to be viewed via /user/{id} like
  # bugs.archlinux.org does.
  user = comment.get("user")
  commented_by = get_if(lambda: args.upstream,
      f"[{user.get('real_name')} ({user.get('user_name')})]" \
      f"({args.upstream}/user/{user.get('id')})",
      f"{user.get('real_name')} ({user.get('user_name')})")
  return f"""\
<small>Commented by {commented_by}</small>

{comment.get('comment_text')}

{attachments_markdown(attachments)}
"""

def module_method(command):
  method_string = f"command_{command}"
  if not method_string in globals():
    # Print out the error string, then return a stub function that
    # just returns 2. In short: this function can be checked against
    # 0 (success) to probe for program failure.
    print(f"error: invalid command '{command}', see --help")
    return lambda args: 2
  return globals().get(method_string)

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

  issues_endpoint = api_endpoint(f"/projects/{repository}/issues")
  logging.info(f"Migrating task {task.get('id')} to {issues_endpoint}.")

  utc = pytz.timezone("UTC")
  date_opened = datetime.fromtimestamp(task["last_edited"], utc) \
      if task["last_edited"] > task["date_opened"] else \
      datetime.fromtimestamp(task["date_opened"], utc)

  attachments = []
  if not args.skip_attachments:
    attachments = task.get("attachments")
    attachments = upload_attachments(args,
        repository, attachments, args.attachments)
    logging.debug(f"Uploaded task attachments: {attachments}.")

  response = requests.post(issues_endpoint, json={
    "access_token": args.token,
    "title": summary_to_title(task.get("summary")),
    "description": task_to_issue(args, task, attachments),
    "created_at": date_opened.isoformat(),
    "weight": task.get("priority_id")
  })

  if not response.status_code in (200, 201):
    raise requests.HTTPError(f"GitLab API returned '{response.status_code}'.")

  data = response.json()

  issue_id = data.get("iid")
  tasks.append((issue_id, repository))

  issue_endpoint = f"{issues_endpoint}/{issue_id}"
  notes_endpoint = f"{issue_endpoint}/notes"

  for comment in task["comments"]:
    logging.info(
        f"Migrating comment {comment.get('comment_id')} to {notes_endpoint}.")

    date_added = datetime.fromtimestamp(comment["last_edited_time"], utc) \
        if comment["last_edited_time"] > comment["date_added"] else \
        datetime.fromtimestamp(comment["date_added"], utc)

    attachments = []
    if not args.skip_attachments:
      attachments = comment.get("attachments")
      attachments = upload_attachments(args,
          repository, attachments, args.attachments)
      logging.debug(f"Uploaded comment attachments: {attachments}.")
    # At this point, attachments should be populated with any attachments
    # that were originally uploaded to Flyspray's comment.

    response = requests.post(notes_endpoint, json={
      "access_token": args.token,
      "body": comment_to_note(args, comment, attachments),
      "created_at": date_added.isoformat()
    })

    if not response.status_code in (200, 201):
      raise requests.HTTPError(
          f"GitLab API returned '{response.status_code}'.")

  if task.get("closed"):
    response = requests.put(issue_endpoint, json={
      "access_token": args.token,
      "state_event": "close"
    })
    if response.status_code != 200:
      raise requests.HTTPError(
          f"GitLab API returned '{response.status_code}'.")

def rollback(args):
  logging.warning("Rolling back by deleting the issues created via HTTP API.")

  global tasks

  # Get current user data.
  data = requests.get(f"{args.base}/api/{args.api}/user").json()
  is_admin = data.get("is_admin", False)

  if is_admin:
    # Delete issue
    pass
  else:
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

# import command handler.
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
  from unittest import mock

  projects = [ task["project"] for task in tasks ]

  data = dict()

  if args.project_mapping:
    with open(args.project_mapping) as f:
      data = json.load(f)

  mappings = [
    data.get(p) if p in data else args.default_target for p in projects
  ]

  def api_base():
    return f"{args.base}/api/{args.api}"

  def user_endpoint():
    return '/'.join([api_base(), "user"])

  def project_endpoint(repo):
    return '/'.join([api_base(), f"projects/{repo}"])

  def upload_endpoint(repo):
    return '/'.join([project_endpoint(repo), "uploads"])

  def issues_endpoint(repo):
    return '/'.join([project_endpoint(repo), "issues"])

  def issue_endpoint(repo, issue):
    return '/'.join([issues_endpoint(repo), f"{issue}"])

  def notes_endpoint(repo, issue):
    return '/'.join([issue_endpoint(repo, issue), "notes"])

  def mock_requests(*route_args, **kwargs):
    rv = dict()

    user_ep = user_endpoint()
    rv[user_ep] = MockResponse({ "is_admin": False })

    for mapping in mappings:
      repo = urllib.parse.quote_plus(mapping)

      # Mock return for this mapping's /project/:id endpoint.
      project_id = 1

      project_ep = project_endpoint(repo)
      if not project_ep in rv:
        rv[project_ep] = MockResponse({
          "id": project_id
        })

      upload_ep = upload_endpoint(repo)
      if not upload_ep in rv:
        rv[upload_ep] = MockResponse({
          "full_path": "/uploads/mocked/path"
        })

      issue_id = 1
      issues_ep = issues_endpoint(repo)

      if not issues_ep in rv:
        rv[issues_ep] = MockResponse({
          "iid": issue_id
        })

      issue_ep = issue_endpoint(repo, issue_id)
      if not issue_ep in rv:
        rv[issue_ep] = MockResponse()

      notes_ep = notes_endpoint(repo, issue_id)
      if not notes_ep in rv:
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
  \t\t\treferencing back to users who made the original tasks and comments.

Example:
  $ flyspray.py | gitlab.py import -m projects.json

Note: This program reads stdin as input for flyspray json data.
"""

  parser = argparse.ArgumentParser(
      formatter_class=lambda prog: argparse.RawTextHelpFormatter(
        prog, max_help_position=80),
      usage="%(prog)s [-hv] [--skip-attachments] [-btmdua ARG]",
      epilog=epilog)

  parser.add_argument("-v", "--verbose", default=False, const=True,
      action="store_const", help="enable debug logging")
  parser.add_argument("-b", "--base", default="http://gitlab.local.net",
      help="GitLab base URL (default: 'http://gitlab.local.net')")
  parser.add_argument("-t", "--token", required=True,
      help="GitLab migration user access token")
  parser.add_argument("-m", "--project-mapping",
      help="path to a project json mapping file " +
           "(default: 'projects.map.json')")
  parser.add_argument("-d", "--default-target", dest="default_target",
      required=True, help="default repository used as the import destination")
  parser.add_argument("-u", "--upstream",
      help="originating Flyspray server's base URL")
  parser.add_argument("-a", "--attachments", default='', required=True,
      help="path to Flyspray attachments directory")
  parser.add_argument("--api", default="v4",
      help="GitLab API version (default: 'v4')")
  parser.add_argument("--skip-attachments", dest="skip_attachments",
      default=False, const=True, action="store_const",
      help="skip attachments altogether")
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
  if not args.api in {"v4", "v3"}:
    return error_log(f"invalid GitLab API version '{args.api}'")

  if not args.skip_attachments:
    if not os.path.isdir(args.attachments):
      return error_log(
          f"invalid attachments directory provided: '{args.attachments}'.")
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

  global upstream
  upstream = args.upstream

  # Process stdin into a json list of task objects.
  if not stdin_available():
    return error_log("Timed out waiting for stdin; input JSON is required.")

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
  except Exception as exc:
    traceback.print_exc() 
  sys.exit(e)
