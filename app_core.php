<?php
// app_core.php: shared logic for Sections 2, 3, and 4.
// Each section file sets these four flags, then includes this file:
//   $escapeOutput   : true = encode output (XSS defense)
//   $validateInput  : true = username must be 3-20 letters, numbers, or underscores
//   $strongPassword : true = password needs 8+ characters, upper, lower, and a digit
//   $useCsp         : true = send a Content Security Policy header

if (!isset($sectionTitle, $escapeOutput, $validateInput, $strongPassword, $useCsp)) {
    die('Open section2_attack_defacement.php, section3_xss_prevention.php, or section4_password_security.php.');
}

session_start();
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

// ---- Block A: output encoding (main XSS defense) ----
// Converts < > " ' & to HTML entities so the browser shows them as text.
// When $escapeOutput is false (Section 2), the raw input is printed, so the attack runs.
function out($value) {
    global $escapeOutput;
    return $escapeOutput
        ? htmlspecialchars((string)$value, ENT_QUOTES | ENT_HTML5, 'UTF-8')
        : (string)$value;
}

// ---- Block B: password rule (Section 4) ----
// At least 8 characters, with a digit, a lowercase letter, and an uppercase letter.
function password_ok($pw) {
    return (bool) preg_match('/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).{8,}$/', $pw);
}

// Writes one row to the "Who did it" activity log.
function log_action(PDO $pdo, $user, $action) {
    $stmt = $pdo->prepare("INSERT INTO activity (username, action) VALUES (?, ?)");
    $stmt->execute([$user, $action]);
}

// ---- Block C: Content Security Policy (Section 3 and 4) ----
// Tells the browser to run only scripts from this site, which blocks injected <script> tags.
if ($useCsp) {
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'");
}

$message = '';
$action  = $_GET['action'] ?? 'home';
$isPost  = $_SERVER['REQUEST_METHOD'] === 'POST';

// ---- REGISTER ----
if ($action === 'register' && $isPost) {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $error = null;

    // Block D: input validation (Sections 3 and 4)
    if ($validateInput && !preg_match('/^[A-Za-z0-9_]{3,20}$/', $username)) {
        $error = 'Username must be 3-20 letters, numbers, or underscores.';
    } elseif ($strongPassword && !password_ok($password)) {
        // Block E: password rule check (Section 4)
        $error = 'Password must be at least 8 characters and include a number, an uppercase letter, and a lowercase letter.';
    }

    if ($error) {
        $message = $error;
    } else {
        try {
            // Block F: prepared statement + password_hash (Section 4 also stores only the hash)
            $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
            $stmt->execute([$username, password_hash($password, PASSWORD_DEFAULT)]);
            log_action($pdo, $username, 'registered');
            $message = 'Registration successful. Please log in.';
        } catch (PDOException $e) {
            $message = 'That username is already taken.';
        }
    }
}

// ---- LOGIN ----
if ($action === 'login' && $isPost) {
    $username = trim($_POST['username'] ?? '');
    $stmt = $pdo->prepare("SELECT password FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $row = $stmt->fetch();

    // Block G: password_verify compares the typed password with the stored hash
    if ($row && password_verify($_POST['password'] ?? '', $row['password'])) {
        session_regenerate_id(true);   // prevents session fixation
        $_SESSION['user'] = $username;
        log_action($pdo, $username, 'logged in');
        header('Location: ' . basename($_SERVER['PHP_SELF']) . '?action=who');
        exit;
    }
    $message = 'Invalid username or password.';
}

// ---- LOGOUT ----
if ($action === 'logout') {
    if (isset($_SESSION['user'])) {
        log_action($pdo, $_SESSION['user'], 'logged out');
    }
    session_destroy();
    header('Location: ' . basename($_SERVER['PHP_SELF']));
    exit;
}

$self = basename($_SERVER['PHP_SELF']);
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title><?= htmlspecialchars($sectionTitle) ?></title>
</head>
<body style="font-family: sans-serif; max-width: 750px; margin: 30px auto;">

<h1><?= htmlspecialchars($sectionTitle) ?></h1>

<?php if ($message): ?>
    <p><b><?= out($message) ?></b></p>
<?php endif; ?>

<?php if (isset($_SESSION['user'])): ?>

    <!-- WHO DID IT page -->
    <p>Logged in as: <b><?= out($_SESSION['user']) ?></b> |
       <a href="<?= $self ?>?action=logout">Logout</a></p>

    <h2>Who did it (activity log)</h2>
    <table border="1" cellpadding="6" style="border-collapse: collapse; width: 100%;">
        <tr><th>Time</th><th>User</th><th>Action</th></tr>
        <?php foreach ($pdo->query("SELECT * FROM activity ORDER BY id DESC LIMIT 20") as $row): ?>
            <tr>
                <td><?= out($row['created_at']) ?></td>
                <td><?= out($row['username']) ?></td>
                <td><?= out($row['action']) ?></td>
            </tr>
        <?php endforeach; ?>
    </table>

<?php else: ?>

    <!-- REGISTER -->
    <h2>Register</h2>
    <form method="post" action="<?= $self ?>?action=register">
        Username: <input name="username" required>
        Password: <input type="password" name="password" required>
        <button type="submit">Register</button>
    </form>
    <p><small>
    <?php if ($strongPassword): ?>
        Password: at least 8 characters, with a number, an uppercase letter, and a lowercase letter.
    <?php else: ?>
        No password rules in this section.
    <?php endif; ?>
    </small></p>

    <!-- LOGIN -->
    <h2>Login</h2>
    <form method="post" action="<?= $self ?>?action=login">
        Username: <input name="username" required>
        Password: <input type="password" name="password" required>
        <button type="submit">Login</button>
    </form>

<?php endif; ?>

</body>
</html>
