<?php
// SECTION 3: XSS prevention.
// Output encoding, username validation, and a Content Security Policy are enabled.
$sectionTitle   = 'Section 3: XSS Prevention';
$escapeOutput   = true;
$validateInput  = true;
$strongPassword = false;
$useCsp         = true;
require __DIR__ . '/app_core.php';
