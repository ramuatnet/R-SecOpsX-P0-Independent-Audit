<?php
// Reflected XSS: the request parameter is written straight to the response
// with no output encoding, so a payload in ?comment= executes on render.
echo $_GET['comment'];
