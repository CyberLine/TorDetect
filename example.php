<?php
require_once 'TorDetect.php';

// check current users ip and
// return true or false
var_dump(Tor::getInstance()->isTorActive());

// check ip of another user
var_dump(Tor::getInstance()->setTarget('1.2.3.4')->isTorActive());
