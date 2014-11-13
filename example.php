<?php
require_once 'src/TorDetect.php';

try {
    // check current users ip and
    // return true or false
    var_dump(Tor::getInstance()->isTorActive());

    // check ip of another user
    var_dump(Tor::getInstance()->setTarget('1.2.3.4')->isTorActive());
} catch (\Exception $e) {
    print $e->getMessage();
}
