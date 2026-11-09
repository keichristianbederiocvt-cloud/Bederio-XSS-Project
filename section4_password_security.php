<?php
// SECTION 4: Stronger login and registration security.
// Builds on Section 3 and adds the password rule (8+ characters, upper, lower, number).
$sectionTitle   = 'Section 4: Password Security (with XSS Prevention)';
$escapeOutput   = true;
$validateInput  = true;
$strongPassword = true;
$useCsp         = true;
require __DIR__ . '/app_core.php';
