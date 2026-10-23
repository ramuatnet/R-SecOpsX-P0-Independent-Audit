<?php
// Output encoding before the response sink: the same request parameter is
// HTML-escaped with ENT_QUOTES, so markup in ?comment= renders inert.
$comment = $_GET['comment'];
echo htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');
