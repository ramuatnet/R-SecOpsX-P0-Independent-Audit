<?php
// Credentials from environment – no hard‑coded secret
$host = getenv("DB_HOST") ?: "localhost";
$user = getenv("DB_USER") ?: "";
$pass = getenv("DB_PASS") ?: "";
$db   = getenv("DB_NAME") ?: "testdb";

$mysqli = new mysqli($host, $user, $pass, $db);
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

// ----- Parameterised query (fixes CWE-89) -----
$name = $_GET['name'] ?? '';
$stmt = $mysqli->prepare("SELECT * FROM users WHERE name = ?");
$stmt->bind_param("s", $name);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    echo $row['username'] . "<br>";
}
$stmt->close();

// ----- Whitelist for command (fixes CWE-78) -----
$cmd = $_GET['cmd'] ?? '';
$allowed = ['ls', 'pwd', 'date'];
$parts = explode(' ', $cmd);
if (!in_array($parts[0] ?? '', $allowed, true)) {
    die("Invalid command");
}
// Use exec with escapeshellarg
$safeCmd = escapeshellcmd($parts[0]);
$output = shell_exec($safeCmd . " " . escapeshellarg(implode(' ', array_slice($parts,1))));
echo $output;

// ----- Path validation (fixes CWE-22) -----
$file = $_GET['file'] ?? '';
if (strpos($file, '..') !== false || strpos($file, '/') === 0) {
    die("Invalid file name");
}
include("/var/www/includes/" . $file);

// ----- Avoid eval altogether (fixes CWE-94) -----
// If dynamic code is truly needed, use a safe sandbox or whitelist.
// Here we simply reject the input.
$code = $_GET['code'] ?? '';
if ($code !== '') {
    die("Code evaluation disabled");
}

$mysqli->close();
?>
