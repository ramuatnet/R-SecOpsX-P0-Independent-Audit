<?php
// ----- Hard‑coded DB credentials (CWE-798) -----
$host = "localhost";
$user = "root";
$pass = "hardcoded_password";
$db   = "testdb";

$mysqli = new mysqli($host, $user, $pass, $db);
if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

// ----- SQL Injection (CWE-89) -----
$userInput = $_GET['name'] ?? ''; // source
$sql = "SELECT * FROM users WHERE name = '$userInput'";
$result = $mysqli->query($sql);
while ($row = $result->fetch_assoc()) {
    echo $row['username'] . "<br>";
}

// ----- Command Injection (CWE-78) -----
$cmd = $_GET['cmd'] ?? '';
system("echo " . $cmd); // vulnerable

// ----- File Include (CWE-22) -----
$file = $_GET['file'] ?? '';
include("/var/www/includes/" . $file); // no validation

// ----- Unsafe eval (CWE-94) -----
$code = $_GET['code'] ?? '';
eval($code); // dangerous

$mysqli->close();
?>
