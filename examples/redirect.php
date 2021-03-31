<?php
# This PHP file shows an example of fetching redirect locations
# from gitlab.py's id mapping output.
#
# It is quite straightforward:
#   1. Read in 'ids.json' into an associative array.
#   2. Parse out the task id from $REQUEST_URI.
#   3. Attempt to find the task id in the json data,
#      which contains the location to its Gitlab issue.
#
$ID_MAPPING = "ids.json";

$string = file_get_contents($ID_MAPPING);
if ($string === false) {
    die("error: no id mapping found at '$ID_MAPPING'.");
}

$json = json_decode($string, true);
if ($json === null) {
    die("error: invalid json found in '$ID_MAPPING'.");
}

$request_uri = $_SERVER["REQUEST_URI"];
$parts = explode('/', $request_uri);

$task_id = end($parts);

if (in_array($task_id, $json)) {
    $issue_endpoint = $json[$task_id];
    http_response_code(303); # See Other
    header("Location: $issue_endpoint");
} else {
    http_response_code(400); # Bad Request
}

?>
