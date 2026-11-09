<?php
// SECTION 2: Defacement attack.
// Vulnerable on purpose: no output encoding, no input validation, no CSP, no password rules.
$sectionTitle   = 'Section 2: Defacement Attack (Vulnerable)';
$escapeOutput   = false;
$validateInput  = false;
$strongPassword = false;
$useCsp         = false;
require __DIR__ . '/app_core.php';
