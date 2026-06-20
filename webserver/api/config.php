<?php
// Serves the filtered nameserver config to the browser.
// Groups whose prefixes don't match the client IP are omitted.

declare(strict_types=1);

header('Content-Type: application/json');
header('Cache-Control: no-store');

$configPath = __DIR__ . '/../dnslg-config.json';
if (!is_readable($configPath)) {
    http_response_code(500);
    echo json_encode(['error' => 'Config file not found or not readable']);
    exit;
}

$raw = file_get_contents($configPath);
$config = json_decode($raw, true);
if ($config === null) {
    http_response_code(500);
    echo json_encode(['error' => 'Config file is not valid JSON']);
    exit;
}

$clientIP = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

// Filter nameserver groups by client IP against each group's prefix list.
$visibleGroups = [];
foreach ($config['nameservers'] ?? [] as $group) {
    $prefixes = $group['prefixes'] ?? [];
    if (empty($prefixes) || clientMatchesPrefixes($clientIP, $prefixes)) {
        $visibleGroups[] = [
            'name'  => $group['name'] ?? '',
            'items' => $group['items'] ?? [],
        ];
    }
}

echo json_encode([
    'nameservers'   => $visibleGroups,
    'defaults'      => $config['defaults'] ?? [],
    'custom'        => $config['custom'] ?? ['enabled' => false],
    'qtypes'        => $config['qtypes'] ?? [],
    'client_ip'     => $clientIP,
    'trust_anchors' => fetchRootAnchors(),
]);

// ---------------------------------------------------------------------------

// Fetches DNSSEC trust anchors from IANA's root-anchors.xml, caching in /tmp for 24 h.
// Returns an array of { key_tag, algorithm, digest_type, digest } objects, or [] on failure.
function fetchRootAnchors(): array
{
    $cacheFile = sys_get_temp_dir() . '/dnslg-root-anchors.json';
    if (is_readable($cacheFile) && (time() - filemtime($cacheFile)) < 86400) {
        $cached = json_decode(file_get_contents($cacheFile), true);
        if (is_array($cached)) {
            return $cached;
        }
    }

    $ctx = stream_context_create([
        'http' => ['timeout' => 10, 'method' => 'GET'],
        'ssl'  => ['verify_peer' => true],
    ]);
    $xml = @file_get_contents('https://data.iana.org/root-anchors/root-anchors.xml', false, $ctx);
    if ($xml === false) {
        return [];
    }

    $doc = @simplexml_load_string($xml);
    if ($doc === false) {
        return [];
    }

    $anchors = [];
    $now = time();
    foreach ($doc->KeyDigest ?? [] as $kd) {
        // Skip entries that have expired.
        $validUntil = (string)($kd['validUntil'] ?? '');
        if ($validUntil !== '' && strtotime($validUntil) < $now) {
            continue;
        }
        $anchors[] = [
            'key_tag'     => (int)(string)$kd->KeyTag,
            'algorithm'   => (int)(string)$kd->Algorithm,
            'digest_type' => (int)(string)$kd->DigestType,
            'digest'      => strtoupper(trim((string)$kd->Digest)),
        ];
    }

    if (!empty($anchors)) {
        @file_put_contents($cacheFile, json_encode($anchors));
    }
    return $anchors;
}

function clientMatchesPrefixes(string $ip, array $prefixes): bool
{
    foreach ($prefixes as $prefix) {
        if (ipInCidr($ip, $prefix)) {
            return true;
        }
    }
    return false;
}

function ipInCidr(string $ip, string $cidr): bool
{
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }

    [$network, $bits] = explode('/', $cidr, 2);
    $bits = (int)$bits;

    $ipBin  = @inet_pton($ip);
    $netBin = @inet_pton($network);

    if ($ipBin === false || $netBin === false) {
        return false;
    }
    if (strlen($ipBin) !== strlen($netBin)) {
        return false; // IPv4 vs IPv6 mismatch
    }

    $byteLen = strlen($ipBin);
    $maxBits = $byteLen * 8;
    if ($bits < 0 || $bits > $maxBits) {
        return false;
    }

    // Compare bit by bit using a mask.
    $fullBytes = intdiv($bits, 8);
    $remainder = $bits % 8;

    if (substr($ipBin, 0, $fullBytes) !== substr($netBin, 0, $fullBytes)) {
        return false;
    }
    if ($remainder > 0) {
        $mask = 0xFF & (0xFF << (8 - $remainder));
        if ((ord($ipBin[$fullBytes]) & $mask) !== (ord($netBin[$fullBytes]) & $mask)) {
            return false;
        }
    }

    return true;
}
