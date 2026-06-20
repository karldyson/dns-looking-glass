<?php
// Validates and proxies a DNS query request to the selected remote Go node.

declare(strict_types=1);

header('Content-Type: application/json');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$body = file_get_contents('php://input');
$req  = json_decode($body, true);
if ($req === null) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON body']);
    exit;
}

$configPath = __DIR__ . '/../dnslg-config.json';
if (!is_readable($configPath)) {
    http_response_code(500);
    echo json_encode(['error' => 'Config file not found']);
    exit;
}

$config = json_decode(file_get_contents($configPath), true);
if ($config === null) {
    http_response_code(500);
    echo json_encode(['error' => 'Config file is not valid JSON']);
    exit;
}

// Validate qtype against the allowed list.
$tag   = (string)($req['tag'] ?? '');
$qname = trim((string)($req['qname'] ?? ''));
$qtype = strtoupper(trim((string)($req['qtype'] ?? 'A')));

if ($qname === '') {
    http_response_code(400);
    echo json_encode(['error' => 'qname is required']);
    exit;
}

$allowedQtypes = $config['qtypes'] ?? [];
if (!in_array($qtype, $allowedQtypes, true)) {
    http_response_code(400);
    echo json_encode(['error' => "qtype '$qtype' is not permitted"]);
    exit;
}

// Resolve node API URL from tag.
$apiUrl  = null;
$nodePort = resolveDefaultPort($config);

foreach ($config['nameservers'] ?? [] as $group) {
    $items = $group['items'] ?? [];
    if (isset($items[$tag])) {
        $item     = $items[$tag];
        $host     = $item['host'] ?? '';
        $itemPort = isset($item['port']) ? (int)$item['port'] : 0;
        if ($itemPort < 1 || $itemPort > 65535) {
            $itemPort = $nodePort;
        }
        $apiUrl = "http://{$host}:{$itemPort}/";
        break;
    }
}

if ($apiUrl === null) {
    http_response_code(400);
    echo json_encode(['error' => "Unknown nameserver tag: '$tag'"]);
    exit;
}

// Build the payload for the Go API (pass through all relevant fields).
$payload = [
    'qname'      => $qname,
    'qtype'      => $qtype,
    'mode'       => $req['mode'] ?? 'localhost',
    'nameserver' => $req['nameserver'] ?? '',
    'port'       => (int)($req['port'] ?? 53),
    'use_tcp'    => (bool)($req['use_tcp'] ?? false),
    'flags'      => [
        'rd'       => (bool)($req['flags']['rd']       ?? true),
        'ad'       => (bool)($req['flags']['ad']       ?? true),
        'cd'       => (bool)($req['flags']['cd']       ?? false),
        'do'       => (bool)($req['flags']['do']       ?? false),
        'validate' => (bool)($req['flags']['validate'] ?? false),
    ],
    'edns'              => [
        'udp_size' => (int)($req['edns']['udp_size'] ?? 1232),
        'options'  => $req['edns']['options'] ?? [],
    ],
    'trust_anchor_mode' => (string)($req['trust_anchor_mode'] ?? 'iana'),
    'trust_anchors'     => $req['trust_anchors'] ?? [],
];

$apiStart = microtime(true);
$result   = postJSON($apiUrl, $payload);
$apiMs    = round((microtime(true) - $apiStart) * 1000, 2);

if ($result === null) {
    http_response_code(502);
    echo json_encode(['error' => "Failed to reach remote node at $apiUrl"]);
    exit;
}

// Inject the PHP-measured round-trip time alongside the Go-measured DNS time.
$result['api_ms'] = $apiMs;

echo json_encode($result);

// ---------------------------------------------------------------------------

function resolveDefaultPort(array $config): int
{
    $port = (int)($config['api']['port'] ?? 53080);
    return ($port >= 1 && $port <= 65535) ? $port : 53080;
}

function postJSON(string $url, array $data): ?array
{
    $json = json_encode($data);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $json,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'Accept: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_CONNECTTIMEOUT => 5,
    ]);

    $body = curl_exec($ch);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($body === false || $err !== '') {
        error_log("dnslg query.php curl error for $url: $err");
        return null;
    }

    $decoded = json_decode($body, true);
    return is_array($decoded) ? $decoded : null;
}
